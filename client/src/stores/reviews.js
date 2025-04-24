import { defineStore } from 'pinia';
import reviewService from '@/services/review.service.js';


export const useReviewStore = defineStore('review', {
    state: () => {
        return {
            reviewsMedia: [],
            formComment: {},
            reviewsUser: []
        }
    },

    actions: {
        async createComment(userId, mediaId, token) {
            var formData = {
                userID: userId,
                mediaID: mediaId,
                ...this.formComment
            }
            return await reviewService.post(formData, token);
        },
    },
})