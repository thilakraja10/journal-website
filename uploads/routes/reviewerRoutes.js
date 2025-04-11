const express = require("express");
const Paper = require("../models/Paper");

const router = express.Router();

// Fetch all papers
router.get("/get-papers", async (req, res) => {
    try {
        const papers = await Paper.find();
        res.json(papers);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Assign Reviewer
router.post("/assign-reviewer", async (req, res) => {
    const { paperId, reviewerName } = req.body;

    try {
        const updatedPaper = await Paper.findOneAndUpdate(
            { paperId: paperId },
            { $set: { reviewer: reviewerName } },
            { new: true } // Return updated document
        );

        if (!updatedPaper) {
            return res.status(404).json({ message: "Paper not found" });
        }

        res.json({ message: "Reviewer assigned successfully", updatedPaper });
    } catch (error) {
        res.status(500).json({ message: "Error assigning reviewer", error });
    }
});


module.exports = router;
