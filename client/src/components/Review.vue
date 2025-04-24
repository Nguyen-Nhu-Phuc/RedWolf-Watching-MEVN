<template>
    <div class="container-fluid mx-0 mt-4 py-1 media-review">
        <div class="container">
            <div class="row">
                <div class="categories col-12">
                    <h4 class="title-menu">
                        REVIEWS
                        <span class="separate"></span>
                    </h4>
                </div>
            </div>

            <div class="row evaluation-input" v-if="userStore.isLoggedin">
                <div class="col-2" v-if="widthScreen < 740">
                    <Avatar :fullName="userStore.account.fullName" style="padding: 28% 100%;" />
                </div>

                <div class="col-2" v-else>
                    <Avatar :fullName="userStore.account.fullName" style="padding: 10% 0; width: 50% !important;" />
                </div>

                <div class="col-10">
                    <div class="comment ml-3 w-100">
                        <div class="comment-header w-100">
                            <h5 class="name-user">{{ userStore.account.fullName }}</h5>
                        </div>
                        <form method="POST" class="w-75" @submit.prevent="postComment">
                            <textarea class="comment-input small text-justify w-100" rows="3"
                                v-model="reviewStore.formComment.content">
                                </textarea>
                            <div class="form-group sections row my-2">
                                <div class="col-12 p-0">
                                    <label class="col-form-label form-control-label text-light mr-2">
                                        <font-awesome-icon :icon="['fas', 'trophy']" class="text-warning" />
                                        Appreciate
                                    </label>
                                    <input type="number" placeholder="?/100" id="appreciate" min="0" max="100"
                                        v-model="reviewStore.formComment.rate">
                                </div>
                                <div class="w-100 my-2"></div>
                                <div class="col-12 p-0">
                                    <div class="d-flex justify-content-end w-100">
                                        <input type="reset" class="btn btn-secondary mr-2" value="Cancel">
                                        <input type="submit" class="btn btn-primary" value="Save Changes">
                                    </div>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>

            <div v-for="(review, index) in this.reviewStore.reviewsMedia" :key="index">
                <div class="row evaluation" v-if="review.content">
                    <div class="col-2 col-lg-1 p-0 text-center">
                        <Avatar :fullName="review.userID.fullName" :key="review.userID.fullName" />
                    </div>

                    <div class="col-10 col-lg-11 evaluation-comment-right">
                        <div class="comment ml-3 w-100">

                            <div class="comment-header w-100">
                                <h5 class="name-user">{{ review.userID.fullName }}</h5>
                                <div class="d-flex align-items-center">
                                    <span class="date">{{ review.date.split('T')[0] }}</span>
                                    <button class="btn btn-danger btn-delete rounded-0 p-0" type="button"
                                        data-toggle="tooltip" data-placement="top" title="Delete"
                                        @click="removeComment(review._id)"
                                        v-if="userStore.account != null && review.userID._id === userStore.account._id">
                                        <font-awesome-icon :icon="['fas', 'trash-alt']" class="text-danger" />
                                    </button>
                                </div>
                            </div>

                            <div class="comment-content-collapse">
                                <p class="comment-content-apart show small text-justify">{{ review.content }}</p>
                                <div :id="'collapse' + review._id" class="comment-content-fully">
                                    <p class="small text-justify text-white" style="font-size: 1.2rem;">
                                        {{ review.content }}
                                    </p>
                                </div>
                                <button class="btn btn-link btn-toggle-collapse p-0 ml-0" type="button"
                                    @click="readFullyCmt(index)" style="display: none;">
                                    Read more
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>
<script>
import Avatar from './Avatar.vue';

import { useUserStore } from '@/stores/user.js';
import { useReviewStore } from '@/stores/reviews.js';
import { useMediaStore } from '@/stores/media.js';

import reviewService from '@/services/review.service.js';
import mediaService from '@/services/media.service.js';

export default {
    setup() {
        const userStore = useUserStore();
        const reviewStore = useReviewStore();
        const mediaStore = useMediaStore();
        return {
            userStore,
            reviewStore,
            mediaStore
        }
    },

    components: { Avatar },

    computed: {
        widthScreen() {
            return window.innerWidth;
        }
    },

    methods: {
        async postComment() {
            const userId = this.userStore.account._id;
            const mediaId = this.$route.params.id;
            const token = this.userStore.account.token;
            const res = await this.reviewStore.createComment(userId, mediaId, token);
            if (res.status == 201) {
                this.reviewStore.formComment = {};
                this.mediaStore.media = await mediaService.getDetail(mediaId);
                this.reviewStore.reviewsMedia = await reviewService.getReviewsMedia(mediaId);
            }
        },

        async removeComment(id) {
            const mediaId = this.$route.params.id;
            const res = await reviewService.remove(id, this.userStore.account.token);
            this.mediaStore.media = await mediaService.getDetail(mediaId);
            this.reviewStore.reviewsMedia = await reviewService.getReviewsMedia(mediaId);
        },

        async handleReadMoreCmt() {
            const cmtContentApart = document.getElementsByClassName("comment-content-apart");
            var text = [];
            for (let i = 0; i < cmtContentApart.length; i++) {
                if (cmtContentApart[i]) {
                    text.push(cmtContentApart[i]);
                }
            }
            for (let i = 0; i < text.length; i++) {
                const element = text[i];
                if (element.innerText.length > 150) {
                    element.innerHTML = element.innerText.substr(0, 150);
                    document.getElementsByClassName('btn-toggle-collapse')[i].style.display = 'flex';
                }
            }
        },

        async readFullyCmt(index) {
            var cmtContentApart = document.getElementsByClassName("comment-content-apart")[index];
            cmtContentApart.classList.toggle("show");
            var cmtContentFully = document.getElementsByClassName("comment-content-fully")[index];
            cmtContentFully.classList.toggle("show");

            var btnToggleCollapse = document.getElementsByClassName('btn-toggle-collapse')[index];
            if (cmtContentApart.classList.contains("show")) {
                btnToggleCollapse.innerHTML = "Read more";
            }
            else {
                btnToggleCollapse.innerHTML = "Collapse";
            }
        }
    },

    updated() {
        this.handleReadMoreCmt();
    },

    mounted() {
        this.handleReadMoreCmt();
    }
}
</script>
<style lang="scss" scoped>
@import '@/assets/styles/detailMedia.scss';

.comment-content-apart,
.comment-content-fully {
    display: none;

    &.show {
        display: block;
    }
}

.btn-toggle-collapse:focus {
    box-shadow: none;
}
</style>