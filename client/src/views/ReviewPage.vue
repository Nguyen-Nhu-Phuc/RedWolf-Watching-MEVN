<template>
    <div class="review">
        <div class="container mt-4">
            <div class="categories col-12">
                <h4 class="title-menu text-uppercase">
                    Your Review
                    <span class="separate"></span>
                </h4>
            </div>

            <div class="my-4 list-review" v-for="(review, index) in reviewStore.reviewsUser" :key="index">
                <div class="review-item" :class="review._id">
                    <img :src="review.mediaID.posters[1]" class="review-poster-media" alt="poster media">
                    <div class="review-detail flex-grow-1 text-light mx-3">
                        <h4 class="media-name mb-2">{{ review.mediaID.name }}</h4>
                        <p>{{ review.date.split('T')[0] }}</p>

                        <p :class="'collapse' + review._id" v-if="review.content" class="comment-content-apart show">
                            {{ review.content }}
                        </p>
                        <div :class="'collapse' + review._id" :id="'collapse' + review._id" class="comment-content-fully"
                            v-if="review.content">
                            <p class="small text-justify text-white" style="font-size: 1rem;">
                                {{ review.content }}
                            </p>
                        </div>

                        <button v-if="review.content" :class="'collapse' + review._id"
                            class="btn btn-link btn-toggle-collapse p-0 ml-0" type="button"
                            @click="readFullyCmt(review._id)" style="display: none;">
                            Read more
                        </button>

                        <span class="appreciate" v-if="review.rate > 0">
                            <font-awesome-icon :icon="['fas', 'trophy']" class="text-warning" />
                            {{ review.rate }}/100
                        </span>
                    </div>

                    <button type="button" class="btn btn-remove p-0 rounded-0 text-light" data-toggle="tooltip"
                        data-placement="top" @click="removeCommet(review._id)">
                        Remove <font-awesome-icon :icon="['fas', 'trash-alt']" />
                    </button>
                </div>
            </div>
        </div>
    </div>
</template>

<script>
import { useUserStore } from '@/stores/user.js';
import { useReviewStore } from '@/stores/reviews.js';

import reviewService from '@/services/review.service.js';

export default {
    setup() {
        const userStore = useUserStore();
        const reviewStore = useReviewStore();
        return {
            userStore,
            reviewStore
        }
    },

    methods: {
        async handleSetValue() {
            const userId = this.userStore.account._id;
            const token = this.userStore.account.token;
            this.reviewStore.reviewsUser = await reviewService.reviewsUser(userId, token);
        },

        async removeCommet(id) {
            const res = await reviewService.remove(id, this.userStore.account.token);
            await this.handleSetValue();
        },

        async handleReadMoreCmt() {
            const cmtContentApart = document.getElementsByClassName('comment-content-apart');
            var text = [];
            for (let i = 0; i < cmtContentApart.length; i++) {
                if (cmtContentApart[i]) {
                    text.push(cmtContentApart[i]);
                }
            }
            for (let i = 0; i < text.length; i++) {
                const element = text[i];
                if (element.innerText.length > 140) {
                    element.innerHTML = element.innerText.substr(0, 140);
                    document.getElementsByClassName('btn-toggle-collapse')[i].style.display = 'flex';
                }
            }
        },

        async readFullyCmt(idInput) {
            // var cmtContentApart = document.getElementsByClassName('comment-content-apart')[index];
            // cmtContentApart.classList.toggle("show");
            // var cmtContentFully = document.getElementsByClassName("comment-content-fully")[index];
            // cmtContentFully.classList.toggle("show");

            // var btnToggleCollapse = document.getElementsByClassName('btn-toggle-collapse')[index];
            var cmtContentApart = document.getElementsByClassName(`comment-content-apart collapse${idInput}`)[0];
            cmtContentApart.classList.toggle("show");
            var cmtContentFully = document.getElementsByClassName(`comment-content-fully collapse${idInput}`)[0];
            cmtContentFully.classList.toggle("show");

            var btnToggleCollapse = document.getElementsByClassName(`btn-toggle-collapse collapse${idInput}`)[0];
            console.log(btnToggleCollapse);
            console.log(cmtContentApart.classList.contains("show"));
            if (cmtContentApart.classList.contains("show")) {
                btnToggleCollapse.innerHTML = "Read more";
            }
            else {
                btnToggleCollapse.innerHTML = "Collapse";
            }
        }
    },

    async created() {
        await this.handleSetValue();
        await this.handleReadMoreCmt();
    },
}
</script>

<style lang="scss" scoped>
@import '@/assets/styles/review.scss';

.media-name {
    margin-top: 30px;
}

.comment-content-apart,
.comment-content-fully {
    display: none;
    margin-bottom: 30px;

    &.show {
        display: block;
    }
}

.btn-toggle-collapse {
    margin-top: -26px;
}

.btn-toggle-collapse:focus {
    box-shadow: none;
}
</style>