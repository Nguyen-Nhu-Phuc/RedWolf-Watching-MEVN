import { defineStore } from 'pinia';

import favoritesService from '@/services/favorites.service.js';

export const useFavoritesStore = defineStore('favorites', {
    state: () => {
        return {
            favorites: null
        }
    },

    getters: {
        medias() {
            return this.favorites.mediaID;
        }
    },

    actions: {
        getMediaIDRemove(media) {
            return media._id;
        },

        async markFavorited(id) {
            if (this.favorites && this.medias.length > 0) {
                for (let i = 0; i < this.medias.length; i++) {
                    var check = await this.medias[i]._id == id;
                    if (check) {
                        document.getElementsByClassName('font-favorites')[0].classList.add('active-favorites');
                        break;
                    }
                }
            }
        },

        async pushFavorites(accountID, mediaId, token) {
            var datas = {
                userID: accountID,
                mediaID: mediaId
            }
            const res = await favoritesService.push(datas, token);
            if (res.status == 201) {
                document.getElementsByClassName('font-favorites')[0].classList.add('active-favorites');
                this.favorites = await favoritesService.getList(token);
            }
        }
    }
});
