
const express = require('express');
const cors = require('cors');
const path = require('path');
const multer = require('multer');

try {
    process.loadEnvFile(path.join(__dirname, '.env'));
} catch (error) {
    console.log('.env loading skipped:', error.message);
}

const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

const scanHistory = [];
const pendingScans = new Map();
const pendingFileScans = new Map();

const VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3';

const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 32 * 1024 * 1024
    }
});

// Decode filename if it was incorrectly interpreted as Latin-1.
function fixFileNameEncoding(name) {
    if (!name || typeof name !== 'string') {
        return 'Unknown file';
    }

    try {
        // Only attempt conversion when typical UTF-8-as-Latin-1 characters appear.
        if (/[ÃÂØÙ]/.test(name)) {
            const decoded = Buffer.from(name, 'latin1').toString('utf8');

            if (decoded && !decoded.includes('\uFFFD')) {
                return decoded;
            }
        }
    } catch (error) {
        console.error('Filename encoding error:', error);
    }

    return name;
}

function getScanRisk(stats = {}, type = 'file') {
    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);

    if (malicious > 0) {
        return {
            riskLevel: 'High',
            message: `Warning: Malicious ${type} detected!`
        };
    }

    if (suspicious > 0) {
        return {
            riskLevel: 'Medium',
            message: `Suspicious ${type} detected. Use caution.`
        };
    }

    return {
        riskLevel: 'Low',
        message: `No malicious detections reported. This does not guarantee the ${type} is safe.`
    };
}

function normalizeStats(stats = {}) {
    return {
        malicious: Number(stats.malicious || 0),
        suspicious: Number(stats.suspicious || 0),
        harmless: Number(stats.harmless || 0),
        undetected: Number(stats.undetected || 0),
        timeout: Number(stats.timeout || 0)
    };
}

app.get('/', (req, res) => {
    res.send('CyberGuard Backend is Running!');
});

// ==========================================
// URL SCANNING
// ==========================================

app.post('/api/scan/url', async (req, res) => {
    try {
        const { url, analysisId } = req.body || {};
        const apiKey = process.env.VIRUSTOTAL_API_KEY;

        if (!apiKey) {
            return res.status(500).json({
                status: 'error',
                message: 'VirusTotal API key is missing'
            });
        }

        if (!analysisId) {
            if (!url) {
                return res.status(400).json({
                    status: 'error',
                    message: 'Please provide a URL'
                });
            }

            let parsedUrl;

            try {
                parsedUrl = new URL(url);
            } catch {
                return res.status(400).json({
                    status: 'error',
                    message: 'Invalid URL'
                });
            }

            if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
                return res.status(400).json({
                    status: 'error',
                    message: 'Only HTTP and HTTPS URLs are supported'
                });
            }

            const scanResponse = await fetch(`${VIRUSTOTAL_URL}/urls`, {
                method: 'POST',
                headers: {
                    'x-apikey': apiKey,
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({
                    url: parsedUrl.href
                }),
                signal: AbortSignal.timeout(20000)
            });

            const scanData = await scanResponse.json();

            if (!scanResponse.ok) {
                return res.status(502).json({
                    status: 'error',
                    message: 'VirusTotal scanning service error',
                    details: scanData.error?.message || 'Unknown API error'
                });
            }

            const newAnalysisId = scanData.data?.id;

            if (!newAnalysisId) {
                return res.status(502).json({
                    status: 'error',
                    message: 'Analysis ID was not returned'
                });
            }

            pendingScans.set(newAnalysisId, parsedUrl.href);

            return res.json({
                status: 'pending',
                url: parsedUrl.href,
                analysisId: newAnalysisId,
                riskLevel: 'Pending',
                message: 'URL submitted successfully. Analysis is in progress.'
            });
        }

        const savedUrl = pendingScans.get(analysisId);

        if (!savedUrl) {
            return res.status(404).json({
                status: 'error',
                message: 'URL analysis not found. Please submit the URL again.'
            });
        }

        const reportResponse = await fetch(
            `${VIRUSTOTAL_URL}/analyses/${encodeURIComponent(analysisId)}`,
            {
                headers: {
                    'x-apikey': apiKey
                },
                signal: AbortSignal.timeout(20000)
            }
        );

        const reportData = await reportResponse.json();

        if (!reportResponse.ok) {
            return res.status(502).json({
                status: 'error',
                message: 'Could not retrieve scan report',
                details: reportData.error?.message || 'Unknown API error'
            });
        }

        const attributes = reportData.data?.attributes;

        if (attributes?.status !== 'completed') {
            return res.json({
                status: 'pending',
                url: savedUrl,
                analysisId,
                riskLevel: 'Pending',
                message: 'Analysis is still in progress.'
            });
        }

        const stats = normalizeStats(attributes.stats);
        const result = getScanRisk(stats, 'URL');

        scanHistory.push({
            type: 'url',
            target: savedUrl,
            ...result,
            stats,
            date: new Date()
        });

        pendingScans.delete(analysisId);

        return res.json({
            status: 'success',
            url: savedUrl,
            ...result,
            stats
        });

    } catch (error) {
        console.error('URL scan error:', error);

        return res.status(500).json({
            status: 'error',
            message: 'URL scan failed. Please try again.'
        });
    }
});

// ==========================================
// FILE SCANNING - VIRUSTOTAL
// ==========================================

async function getFileAnalysis(req, res) {
    try {
        const { analysisId, fileName } = req.body || {};
        const apiKey = process.env.VIRUSTOTAL_API_KEY;

        if (!apiKey) {
            return res.status(500).json({
                status: 'error',
                message: 'VirusTotal API key is missing'
            });
        }

        if (!analysisId) {
            return res.status(400).json({
                status: 'error',
                message: 'Analysis ID is required.'
            });
        }

        const savedFile = pendingFileScans.get(analysisId);
        const currentFileName = fixFileNameEncoding(
            savedFile?.fileName || fileName || 'Unknown file'
        );

        const reportResponse = await fetch(
            `${VIRUSTOTAL_URL}/analyses/${encodeURIComponent(analysisId)}`,
            {
                headers: {
                    'x-apikey': apiKey
                },
                signal: AbortSignal.timeout(20000)
            }
        );

        const reportData = await reportResponse.json();

        if (!reportResponse.ok) {
            return res.status(502).json({
                status: 'error',
                message: 'Could not retrieve file analysis',
                details: reportData.error?.message || 'Unknown API error'
            });
        }

        const attributes = reportData.data?.attributes;

        if (attributes?.status !== 'completed') {
            return res.json({
                status: 'pending',
                analysisId,
                fileName: currentFileName,
                riskLevel: 'Pending',
                message: 'File analysis is still in progress.'
            });
        }

        const stats = normalizeStats(attributes.stats);
        const result = getScanRisk(stats, 'file');

        scanHistory.push({
            type: 'file',
            target: currentFileName,
            ...result,
            stats,
            date: new Date()
        });

        pendingFileScans.delete(analysisId);

        return res.json({
            status: 'success',
            fileName: currentFileName,
            ...result,
            stats
        });

    } catch (error) {
        console.error('File report error:', error);

        return res.status(500).json({
            status: 'error',
            message: 'Could not retrieve file analysis.'
        });
    }
}

app.post('/api/scan/file', (req, res) => {

    if (!req.is('multipart/form-data')) {
        return getFileAnalysis(req, res);
    }

    upload.single('file')(req, res, async (uploadError) => {

        if (uploadError) {
            if (uploadError.code === 'LIMIT_FILE_SIZE') {
                return res.status(413).json({
                    status: 'error',
                    message: 'File size exceeds the 32 MB limit.'
                });
            }

            return res.status(400).json({
                status: 'error',
                message: 'Could not receive the uploaded file.'
            });
        }

        try {
            const apiKey = process.env.VIRUSTOTAL_API_KEY;

            if (!apiKey) {
                return res.status(500).json({
                    status: 'error',
                    message: 'VirusTotal API key is missing'
                });
            }

            if (!req.file) {
                return res.status(400).json({
                    status: 'error',
                    message: 'Please upload a file.'
                });
            }

            const file = req.file;
            const fileName = fixFileNameEncoding(file.originalname);

            const formData = new FormData();

            const fileBlob = new Blob(
                [file.buffer],
                {
                    type: file.mimetype || 'application/octet-stream'
                }
            );

            formData.append('file', fileBlob, fileName);

            const scanResponse = await fetch(`${VIRUSTOTAL_URL}/files`, {
                method: 'POST',
                headers: {
                    'x-apikey': apiKey
                },
                body: formData,
                signal: AbortSignal.timeout(60000)
            });

            const scanData = await scanResponse.json();

            if (!scanResponse.ok) {
                console.error('VirusTotal file error:', scanData);

                return res.status(502).json({
                    status: 'error',
                    message: 'VirusTotal file upload failed.',
                    details: scanData.error?.message || 'Unknown API error'
                });
            }

            const newAnalysisId = scanData.data?.id;

            if (!newAnalysisId) {
                return res.status(502).json({
                    status: 'error',
                    message: 'File analysis ID was not returned.'
                });
            }

            pendingFileScans.set(newAnalysisId, {
                fileName
            });

            return res.json({
                status: 'pending',
                fileName,
                analysisId: newAnalysisId,
                riskLevel: 'Pending',
                message: 'File uploaded successfully. Analysis is in progress.'
            });

        } catch (error) {
            console.error('File upload error:', error);

            return res.status(500).json({
                status: 'error',
                message: 'File scanning failed. Please try again.'
            });
        }
    });
});

// ==========================================
// IMAGE SCANNING - SIGHTENGINE AI + DEEPFAKE
// ==========================================

app.post('/api/scan/ai-image', (req, res) => {

    upload.single('file')(req, res, async (uploadError) => {

        if (uploadError) {
            return res.status(400).json({
                status: 'error',
                message: 'Could not receive the uploaded image.'
            });
        }

        try {
            const apiUser = process.env.SIGHTENGINE_API_USER;
            const apiSecret = process.env.SIGHTENGINE_API_SECRET;

            if (!apiUser || !apiSecret) {
                return res.status(500).json({
                    status: 'error',
                    message: 'Sightengine API credentials are missing.'
                });
            }

            if (!req.file) {
                return res.status(400).json({
                    status: '400',
                    message: 'Please upload an image.'
                });
            }

            if (!req.file.mimetype?.startsWith('image/')) {
                return res.status(400).json({
                    status: 'error',
                    message: 'Only image files are supported.'
                });
            }

            const file = req.file;
            const fileName = fixFileNameEncoding(file.originalname);

            const formData = new FormData();

            const imageBlob = new Blob(
                [file.buffer],
                { type: file.mimetype }
            );

            formData.append('media', imageBlob, fileName);
            formData.append('models', 'genai,deepfake');
            formData.append('api_user', apiUser);
            formData.append('api_secret', apiSecret);

            const sightResponse = await fetch(
                'https://api.sightengine.com/1.0/check.json',
                {
                    method: 'POST',
                    body: formData,
                    signal: AbortSignal.timeout(60000)
                }
            );

            const sightData = await sightResponse.json();

            if (!sightResponse.ok || sightData.status !== 'success') {
                console.error('Sightengine error:', sightData);

                return res.status(502).json({
                    status: 'error',
                    message: 'Image analysis failed.',
                    details: sightData.error?.message || 'Sightengine could not analyze this image.'
                });
            }

            const imageType = sightData.type || {};

            const aiScore = typeof imageType.ai_generated === 'number'
                ? imageType.ai_generated
                : null;

            const deepfakeScore = typeof imageType.deepfake === 'number'
                ? imageType.deepfake
                : null;

            if (aiScore === null && deepfakeScore === null) {
                return res.status(502).json({
                    status: 'error',
                    message: 'No analysis scores were returned.'
                });
            }

            const aiPercentage = aiScore === null
                ? null
                : Number((aiScore * 100).toFixed(2));

            const deepfakePercentage = deepfakeScore === null
                ? null
                : Number((deepfakeScore * 100).toFixed(2));

            const aiResult = aiScore === null
                ? 'AI analysis unavailable'
                : aiScore >= 0.5
                    ? 'Likely AI-generated or AI-edited'
                    : 'Low AI-generation probability';

            const deepfakeResult = deepfakeScore === null
                ? 'Deepfake analysis unavailable'
                : deepfakeScore >= 0.5
                    ? 'Possible deepfake detected'
                    : 'Low deepfake probability';

            scanHistory.push({
                type: 'ai-image',
                target: fileName,
                status: 'Completed',
                aiResult,
                aiGeneratedScore: aiPercentage,
                deepfakeResult,
                deepfakeScore: deepfakePercentage,
                date: new Date()
            });

            return res.json({
                status: 'success',
                fileName,
                aiResult,
                aiGeneratedScore: aiPercentage,
                deepfakeResult,
                deepfakeScore: deepfakePercentage,
                message: 'Image analysis completed successfully.',
                note: 'Scores represent model confidence, not guaranteed accuracy.'
            });

        } catch (error) {
            console.error('Image scan error:', error);

            return res.status(500).json({
                status: 'error',
                message: 'Image scanning failed.',
                details: error.name === 'TimeoutError'
                    ? 'Request timed out. Please try again.'
                    : 'Could not complete image analysis.'
            });
        }
    });
});


// ==========================================
// SCAN HISTORY
// ==========================================

app.get('/api/scans/history', (req, res) => {
    res.json({
        status: 'success',
        count: scanHistory.length,
        history: scanHistory
    });
});

// ==========================================
// CHATBOT
// ==========================================

try {
    app.use('/api/chat', require('./chatServer'));
} catch (error) {
    console.log('Chatbot module not loaded:', error.message);
}

// ==========================================
// ERROR HANDLING
// ==========================================

app.use((error, req, res, next) => {
    console.error('Backend error:', error);

    if (error.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({
            status: 'error',
            message: 'File size exceeds the 32 MB limit.'
        });
    }

    res.status(500).json({
        status: 'error',
        message: 'An unexpected server error occurred.'
    });
});

// ==========================================
// START SERVER
// ==========================================

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
