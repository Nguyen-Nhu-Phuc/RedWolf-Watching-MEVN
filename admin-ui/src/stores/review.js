import { defineStore } from 'pinia';
import reviewService from '@/services/review.service.js';

export const useReviewStore = defineStore('review', {
    state: () => {
        return {
            reviews: []
        }
    },

    actions: {
        async detailReviewsUser(token, id) {
            return await reviewService.detailReviews(token, id);
        }
    }
});

