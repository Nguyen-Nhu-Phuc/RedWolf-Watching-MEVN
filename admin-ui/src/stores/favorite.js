import { defineStore } from 'pinia';
import favoriteService from '@/services/favorite.service.js';
import mediaService from '@/services/media.service.js';

export const useFavoriteStore = defineStore('favorite', {
    state: () => {
        return {
            favorites: []
        }
    },

    actions: {
        async detailFavoritesUser(token, id) {
            const res = await favoriteService.detailFavoritesMember(token, id);
            return res;
        }
    }
});

