
// ===============================
// التنقل بين الصفحات
// ===============================

const links = document.querySelectorAll("[data-page]");
const pages = document.querySelectorAll(".page-section");

function showPage(pageName) {
    pages.forEach(page => page.classList.remove("active-page"));

    const selectedPage = document.getElementById(pageName);

    if (selectedPage) {
        selectedPage.classList.add("active-page");
    }

    window.scrollTo({ top: 0, behavior: "smooth" });
}

links.forEach(link => {
    link.addEventListener("click", function (event) {
        event.preventDefault();
        showPage(link.getAttribute("data-page"));
    });
});

// ===============================
// تسجيل الدخول
// ===============================

const loginBtn = document.getElementById("loginBtn");

if (loginBtn) {
    loginBtn.addEventListener("click", () => showPage("login"));
}

const loginForm = document.getElementById("loginForm");

if (loginForm) {
    loginForm.addEventListener("submit", function (event) {
        event.preventDefault();

        const name = document.getElementById("userName").value.trim();
        const phone = document.getElementById("userPhone").value.trim();
        const email = document.getElementById("userEmail").value.trim();

        if (!name || !phone || !email) {
            alert("من فضلك املأ جميع البيانات.");
            return;
        }

        showPage("scan");
    });
}

// ===============================
// زر ابدأ الفحص
// ===============================

const startScanBtn = document.getElementById("startScanBtn");

if (startScanBtn) {
    startScanBtn.addEventListener("click", () => showPage("scan"));
}

// ===============================
// إظهار النتيجة العامة
// ===============================

function showResult(title, text) {
    const result = document.getElementById("scanResult");
    const resultTitle = document.getElementById("resultTitle");
    const resultText = document.getElementById("resultText");

    if (!result || !resultTitle || !resultText) {
        console.error("Result elements are missing from HTML.");
        return;
    }

    resultTitle.textContent = title;
    resultText.textContent = text;
    result.classList.add("show");
}

// ===============================
// أدوات مساعدة للفحص
// ===============================

function wait(milliseconds) {
    return new Promise(resolve => setTimeout(resolve, milliseconds));
}

async function readJsonResponse(response) {
    const text = await response.text();

    try {
        return JSON.parse(text);
    } catch {
        console.error("Unexpected server response:", text);

        throw new Error(
            "السيرفر أرسل استجابة غير متوقعة. تأكدي أن Backend يعمل على المنفذ 5000."
        );
    }
}

// عرض إحصائيات VirusTotal
function formatScanStats(stats = {}, itemType = "ملف") {
    return `تفاصيل الفحص:
${itemType === "ملف" ? "ملفات" : "روابط"} ضارة: ${stats.malicious ?? 0}
${itemType === "ملف" ? "ملفات" : "روابط"} مشبوهة: ${stats.suspicious ?? 0}
${itemType === "ملف" ? "ملفات" : "روابط"} مصنفة سليمة: ${stats.harmless ?? 0}
لم يتم اكتشاف تهديد: ${stats.undetected ?? 0}
انتهت مهلة الفحص: ${stats.timeout ?? 0}

ملاحظة:
(Undetected) تعني أن محرك الفحص لم يصدر اكتشافًا، ولا تعني تأكيد سلامة العنصر.`;
}

// ===============================
// فحص الروابط - VirusTotal
// ===============================

const urlScanBtn = document.getElementById("urlScanBtn");

if (urlScanBtn) {
    urlScanBtn.addEventListener("click", async function () {
        const urlInput = document.getElementById("urlInput");
        const url = urlInput ? urlInput.value.trim() : "";

        if (!url) {
            alert("من فضلك أدخل الرابط أولاً.");
            return;
        }

        urlScanBtn.disabled = true;

        showResult(
            "جاري الفحص...",
            "جاري إرسال الرابط إلى VirusTotal للتحليل الأمني..."
        );

        try {
            const response = await fetch("http://localhost:5000/api/scan/url", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ url })
            });

            const data = await readJsonResponse(response);

            if (!response.ok || data.status === "error") {
                throw new Error(
                    data.details || data.message || "فشل إرسال الرابط للفحص."
                );
            }

            if (!data.analysisId) {
                throw new Error("لم يتم استلام رقم التحليل.");
            }

            const analysisId = data.analysisId;
            let finalResult = null;

            for (let attempt = 0; attempt < 8; attempt++) {
                showResult(
                    "جاري تحليل الرابط...",
                    `تم إرسال الرابط بنجاح.
جاري انتظار نتيجة VirusTotal...
المحاولة ${attempt + 1} من 8`
                );

                await wait(15000);

                const reportResponse = await fetch(
                    "http://localhost:5000/api/scan/url",
                    {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json"
                        },
                        body: JSON.stringify({ analysisId })
                    }
                );

                const reportData = await readJsonResponse(reportResponse);

                if (!reportResponse.ok || reportData.status === "error") {
                    throw new Error(
                        reportData.details ||
                        reportData.message ||
                        "تعذر الحصول على تقرير الفحص."
                    );
                }

                if (reportData.status === "success") {
                    finalResult = reportData;
                    break;
                }
            }

            if (!finalResult) {
                showResult(
                    "التحليل لم يكتمل بعد",
                    "VirusTotal ما زال يحلل الرابط. انتظري قليلًا ثم أعيدي المحاولة."
                );
                return;
            }

            const stats = finalResult.stats || {};

            showResult(
                "نتيجة فحص الرابط",
                `الرابط المدخل: ${finalResult.url}

الحالة: ${finalResult.message}
مستوى الخطر: ${finalResult.riskLevel}

${formatScanStats(stats, "رابط")}`
            );

        } catch (error) {
            console.error("URL Scan Error:", error);
            showResult("تعذر الفحص", error.message);

        } finally {
            urlScanBtn.disabled = false;
        }
    });
}

// ===============================
// فحص الملفات - VirusTotal
// ===============================

const fileScanBtn = document.getElementById("fileScanBtn");

if (fileScanBtn) {
    fileScanBtn.addEventListener("click", async function () {
        const fileInput = document.getElementById("fileInput");
        const file = fileInput?.files?.[0];

        if (!file) {
            alert("من فضلك اختر ملف أولاً.");
            return;
        }

        if (file.size > 32 * 1024 * 1024) {
            alert("حجم الملف أكبر من الحد المسموح به (32 MB).");
            return;
        }

        fileScanBtn.disabled = true;

        showResult(
            "جاري رفع الملف...",
            "يتم إرسال الملف الحقيقي إلى VirusTotal للفحص الأمني..."
        );

        try {
            const formData = new FormData();
            formData.append("file", file);

            const response = await fetch(
                "http://localhost:5000/api/scan/file",
                {
                    method: "POST",
                    body: formData
                }
            );

            const data = await readJsonResponse(response);

            if (!response.ok || data.status === "error") {
                throw new Error(
                    data.details || data.message || "فشل رفع الملف."
                );
            }

            if (!data.analysisId) {
                throw new Error("لم يتم استلام رقم تحليل الملف.");
            }

            const analysisId = data.analysisId;
            let finalResult = null;

            for (let attempt = 0; attempt < 8; attempt++) {
                showResult(
                    "جاري تحليل الملف...",
                    `اسم الملف: ${file.name}

تم رفع الملف بنجاح.
جاري انتظار نتيجة VirusTotal...
المحاولة ${attempt + 1} من 8`
                );

                await wait(15000);

                const reportResponse = await fetch(
                    "http://localhost:5000/api/scan/file",
                    {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json"
                        },
                        body: JSON.stringify({
                            analysisId,
                            fileName: file.name
                        })
                    }
                );

                const reportData = await readJsonResponse(reportResponse);

                if (!reportResponse.ok || reportData.status === "error") {
                    throw new Error(
                        reportData.details ||
                        reportData.message ||
                        "تعذر الحصول على تقرير الملف."
                    );
                }

                if (reportData.status === "success") {
                    finalResult = reportData;
                    break;
                }
            }

            if (!finalResult) {
                showResult(
                    "التحليل لم يكتمل بعد",
                    `اسم الملف: ${file.name}

VirusTotal ما زال يحلل الملف.
يمكنك المحاولة مرة أخرى بعد قليل.`
                );
                return;
            }

            const stats = finalResult.stats || {};

            showResult(
                "نتيجة فحص الملف",
                `اسم الملف: ${finalResult.fileName}

الحالة: ${finalResult.message}
مستوى الخطر: ${finalResult.riskLevel}

${formatScanStats(stats, "ملف")}`
            );

        } catch (error) {
            console.error("File Scan Error:", error);
            showResult("تعذر فحص الملف", error.message);

        } finally {
            fileScanBtn.disabled = false;
        }
    });
}

// ===============================
// فحص الصور - VirusTotal + Sightengine
// ===============================

const imageScanBtn = document.getElementById("imageScanBtn");

if (imageScanBtn) {
    imageScanBtn.addEventListener("click", async function () {
        const fileInput = document.getElementById("imageInput");
        const file = fileInput?.files?.[0];
        const resultBox = document.getElementById("imageScanResult");

        if (!file) {
            alert("من فضلك اختاري صورة أولاً.");
            return;
        }

        if (!file.type.startsWith("image/")) {
            alert("الملف المختار ليس صورة.");
            return;
        }

        if (file.size > 32 * 1024 * 1024) {
            alert("حجم الصورة أكبر من الحد المسموح به (32 MB).");
            return;
        }

        if (!resultBox) {
            console.error("imageScanResult element is missing from HTML.");
            alert("مكان عرض نتيجة فحص الصورة غير موجود في الصفحة.");
            return;
        }

        imageScanBtn.disabled = true;
        resultBox.replaceChildren();

        const loadingMessage = document.createElement("p");
        loadingMessage.textContent =
            "جاري إرسال الصورة إلى VirusTotal وSightengine... قد يستغرق الفحص بعض الوقت.";
        resultBox.appendChild(loadingMessage);

        // إنشاء قسم مستقل لكل نتيجة
        function addImageResult(title, content) {
            const section = document.createElement("div");
            section.className = "mt-3 p-3";
            section.style.border = "1px solid rgba(128,128,128,0.5)";
            section.style.borderRadius = "8px";
            section.style.whiteSpace = "pre-wrap";

            const heading = document.createElement("h5");
            heading.textContent = title;

            const details = document.createElement("p");
            details.className = "mb-0";
            details.textContent = content;

            section.appendChild(heading);
            section.appendChild(details);
            resultBox.appendChild(section);
        }

        // فحص الصور المولدة والتزييف العميق - Sightengine
        async function scanWithSightengine() {
            try {
                const formData = new FormData();
                formData.append("file", file);

                const response = await fetch(
                    "http://localhost:5000/api/scan/ai-image",
                    {
                        method: "POST",
                        body: formData
                    }
                );

                const data = await readJsonResponse(response);

                if (!response.ok || data.status === "error") {
                    throw new Error(
                        data.details || data.message || "فشل تحليل الصورة."
                    );
                }

                const aiScore = data.aiGeneratedScore;
                const deepfakeScore = data.deepfakeScore;

                addImageResult(
                    "🤖 اكتشاف الصور المولّدة بالذكاء الاصطناعي",
                    `النتيجة: ${data.aiResult || "غير متاحة"}
نسبة الثقة: ${
                        aiScore === null || aiScore === undefined
                            ? "غير متاحة"
                            : aiScore + "%"
                    }`
                );

                addImageResult(
                    "🎭 اكتشاف التزييف العميق (Deepfake)",
                    `النتيجة: ${data.deepfakeResult || "غير متاحة"}
نسبة الثقة: ${
                        deepfakeScore === null || deepfakeScore === undefined
                            ? "غير متاحة"
                            : deepfakeScore + "%"
                    }`
                );

            } catch (error) {
                console.error("Sightengine Image Scan Error:", error);

                addImageResult(
                    "🤖 فحص الذكاء الاصطناعي والتزييف العميق - Sightengine",
                    "تعذر إكمال الفحص: " + error.message
                );
            }
        }

        // الفحص الأمني للصورة - VirusTotal
        async function scanWithVirusTotal() {
            try {
                const formData = new FormData();
                formData.append("file", file);

                const uploadResponse = await fetch(
                    "http://localhost:5000/api/scan/file",
                    {
                        method: "POST",
                        body: formData
                    }
                );

                const uploadData = await readJsonResponse(uploadResponse);

                if (
                    !uploadResponse.ok ||
                    uploadData.status === "error" ||
                    !uploadData.analysisId
                ) {
                    throw new Error(
                        uploadData.details ||
                        uploadData.message ||
                        "لم يتم بدء الفحص الأمني للصورة."
                    );
                }

                let finalResult = null;

                for (let attempt = 0; attempt < 8; attempt++) {
                    await wait(15000);

                    const reportResponse = await fetch(
                        "http://localhost:5000/api/scan/file",
                        {
                            method: "POST",
                            headers: {
                                "Content-Type": "application/json"
                            },
                            body: JSON.stringify({
                                analysisId: uploadData.analysisId,
                                fileName: file.name
                            })
                        }
                    );

                    const reportData = await readJsonResponse(reportResponse);

                    if (!reportResponse.ok || reportData.status === "error") {
                        throw new Error(
                            reportData.details ||
                            reportData.message ||
                            "تعذر الحصول على تقرير VirusTotal."
                        );
                    }

                    if (reportData.status === "success") {
                        finalResult = reportData;
                        break;
                    }
                }

                if (!finalResult) {
                    throw new Error(
                        "لم يكتمل تحليل VirusTotal في الوقت المحدد. يمكنك إعادة المحاولة لاحقًا."
                    );
                }

                const stats = finalResult.stats || {};

                addImageResult(
                    "🛡️ الفحص الأمني للصورة - VirusTotal",
                    `اسم الصورة: ${finalResult.fileName || file.name}

الحالة: ${finalResult.message || "اكتمل الفحص"}
مستوى الخطورة: ${finalResult.riskLevel || "غير محدد"}

${formatScanStats(stats, "ملف")}`
                );

            } catch (error) {
                console.error("VirusTotal Image Scan Error:", error);

                addImageResult(
                    "🛡️ الفحص الأمني للصورة - VirusTotal",
                    "تعذر إكمال الفحص: " + error.message
                );
            }
        }

        try {
            // تشغيل الخدمتين بشكل مستقل
            await Promise.all([
                scanWithSightengine(),
                scanWithVirusTotal()
            ]);

            addImageResult(
                "ملاحظة مهمة",
                "فحص VirusTotal يختبر الملف بحثًا عن التهديدات الأمنية، بينما Sightengine يحلل مؤشرات إنشاء الصورة بالذكاء الاصطناعي والتزييف العميق. هذه النتائج تقديرات من خدمات التحليل وليست ضمانًا مطلقًا."
            );

        } catch (error) {
            console.error("Image Scan Error:", error);

            addImageResult(
                "خطأ",
                "حدث خطأ غير متوقع أثناء فحص الصورة: " + error.message
            );

        } finally {
            imageScanBtn.disabled = false;
        }
    });
}

// ===============================
// سجل الفحوصات
// ===============================

async function fetchAndDisplayHistory() {
    try {
        const response = await fetch("http://localhost:5000/api/scans/history");
        const data = await readJsonResponse(response);

        const tbody = document.getElementById("historyTableBody");

        if (!tbody) return;

        tbody.replaceChildren();

        if (data.status === "success" && data.history.length > 0) {
            data.history.forEach(item => {
                const row = document.createElement("tr");

                const typeCell = document.createElement("td");
                typeCell.textContent =
                    item.type === "file" ? "📁 ملف" :
                    item.type === "ai-image" ? "🖼️ صورة" : "🔗 رابط";

                const targetCell = document.createElement("td");
                targetCell.textContent = item.target || "غير محدد";
                targetCell.style.color = "#38bdf8";

                const riskCell = document.createElement("td");
                riskCell.textContent = item.riskLevel || item.status || "غير محدد";
                riskCell.style.fontWeight = "bold";

                const messageCell = document.createElement("td");
                messageCell.textContent = item.message || item.status || "لا توجد تفاصيل";

                row.append(typeCell, targetCell, riskCell, messageCell);
                tbody.appendChild(row);
            });
        } else {
            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 4;
            cell.textContent = "لا توجد فحوصات مسجلة حتى الآن";
            cell.style.padding = "15px";
            cell.style.textAlign = "center";

            row.appendChild(cell);
            tbody.appendChild(row);
        }

    } catch (error) {
        console.error("History Error:", error);
        alert("تعذر الاتصال بالسيرفر لجلب السجل.");
    }
}
