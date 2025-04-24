import mongoose from 'mongoose';
import mongooseDelete from 'mongoose-delete';

var mediaSchema = new mongoose.Schema({
    userID: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: { type: String, required: true },
    description: { type: String, required: true },
    posters: [{ type: String }],
    category: { type: String, enum: ['movie', 'tv series'], required: true },
    genre: [{ type: String, required: true }],
    language: { type: String, required: true },
    year: { type: Number, required: true },
    eppisodes: [
        {
            videoUrl: { type: String },
            number: { type: Number, default: 1 },
        }
    ],
    rate: { type: Number, default: 0 },
    numberRater: { type: Number, default: 0 },
    casts: [
        {
            name: { type: String, required: true },
            character: { type: String },
            avatar: { type: String, required: true }
        }
    ]
}, { collection: 'medias' })

mediaSchema.plugin(mongooseDelete, {
    deletedAt: true,
    overrideMethods: true
});

const Media = mongoose.model('Media', mediaSchema);
export default Media;