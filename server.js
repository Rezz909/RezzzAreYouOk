import express from "express";

const app = express();

app.use(express.json());

app.get("/", (req, res) => {
    res.json({
        ok: true,
        service: "Rezzz Backend",
        message: "Backend berhasil online!"
    });
});

app.get("/health", (req, res) => {
    res.json({
        ok: true,
        service: "rezzz-backend"
    });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Rezzz Backend berjalan di port ${PORT}`);
});
