import express, { urlencoded } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';

import { connectDB } from './config/db.js';
import { route } from './routes/index.js';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(urlencoded({ extended: false }));
connectDB();

const port = process.env.PORT || 5000;

// Routes init
route(app);

app.get('/', (req, res) => {
    res.send('Hello World!')
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
})