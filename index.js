const express = require('express');
const app = express();

const PORT = process.env.PORT || 3000;

// Health check
app.get('/', (req, res) => {
  res.send('Server is up and running!');
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on port ${PORT}`);
});