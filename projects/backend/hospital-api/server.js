const app = require("./app");
const PORT = 3001;

app.listen(PORT, () => {
    console.log(`✅ EMR server is running at http://localhost:${PORT}`);
});
