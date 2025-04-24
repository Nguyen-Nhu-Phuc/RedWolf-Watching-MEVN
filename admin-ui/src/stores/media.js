import { defineStore } from 'pinia';
import mediaService from '@/services/media.service.js';

export const useMediaStore = defineStore('media', {
    state: () => {
        return {
            media: null,
            idRestore: {
                "id": null
            },
            optionGenre: [
                'Action',
                'Adventure',
                'Music',
                'Crime',
                'Mystery',
                'Thriller',
                'Drama',
                'Family',
                'History',
                'Sci-Fi',
                'Comedy',
                'Romance',
                'Biography',
                'Fantasy'
            ],
            formMedia: {
                userID: '',
                name: '',
                description: '',
                posters: [
                    '',
                    '',
                ],
                category: '',
                genre: [
                    ''
                ],
                language: '',
                year: 1999,
                eppisodes: [
                    {
                        videoUrl: '',
                        number: 1
                    }
                ],
                rate: 0,
                numberRater: 0,
                casts: [
                    {
                        "name": "",
                        "character": "",
                        "avatar": ""
                    }
                ]
            },
            listMovies: [],
            listSeries: [],
            trash: []
        }
    },

    getters: {
        scoreInEditView() {
            if (this.formMedia.numberRater > 0) {
                return Math.round(this.formMedia.rate / this.formMedia.numberRater);
            }
            return 0;
        },
    },

    actions: {
        async getList() {
            this.listMovies = await mediaService.popularMovies();
            this.listSeries = await mediaService.popularSeries();
        },

        async getTrash(token) {
            this.trash = await mediaService.trash(token);
        },

        async deleteMedia(token, id) {
            const res = await mediaService.delete(token, id);
            if (res.status == 200) {
                $('#remove-media-modal').modal('hide');
                $('.modal-backdrop').remove();
                await this.getList();
            }
        },

        async restoreMedia(token, id) {
            this.idRestore.id = await id;
            const res = await mediaService.restore(token, this.idRestore);
            if (res.status == 200) {
                await this.getTrash(token);
            }
        },

        async forceDelete(token, id) {
            const res = await mediaService.realDelete(token, id);
            if (res.status == 200) {
                await this.getTrash(token);
            }
        }
    }
});