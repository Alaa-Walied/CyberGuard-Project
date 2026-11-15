const express = require('express');
const router = express.Router();

router.post('/', (req, res) => {
    const userMessage = req.body.message || "";
    console.log("Received chat message:", userMessage);

    res.json({
        status: "success",
        reply: "أهلاً بكِ يا آلاء! أنا مساعد CyberGuard الذكي، كيف يمكنني مساعدتك في أمان موقعك اليوم؟"
    });
});

module.exports = router;