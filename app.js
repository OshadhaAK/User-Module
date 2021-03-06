const express = require('express');
const app = express();
const mongoose = require('mongoose');
const dotenv = require('dotenv');



const authRoute = require('./routes/auth');
const postRoutes = require('./routes/posts');

dotenv.config();

mongoose.connect(
    process.env.DB_CONNECT,
    { useNewUrlParser: true, useUnifiedTopology: true },
    () => console.log('DB connected!')
)


app.use(express.json());





app.use('/api/user', authRoute);
app.use('/api/posts', postRoutes);

app.listen(3000, () => console.log('Server up and running'));
