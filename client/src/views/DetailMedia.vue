<template>
    <div class="detail-media" v-if="this.mediaStore.media">
        <div class="container-fluid m-0 p-0 media-intro">
            <div class="background-img-intro"></div>

            <div class="media-desc w-100">
                <img class="media-poster" :src="mediaStore.media.posters[1]" alt="poster media">

                <div class="media-side-right">
                    <h2 class="media-name text-uppercase">{{ mediaStore.media.name }}</h2>

                    <div class="media-rating my-2">
                        <RatingCircle :key="generateKey(mediaStore.media._id, mediaStore.media.rate)" />
                        <span class="mr-2"></span>
                        <span class="genre mr-1" v-for="(gen, index) in mediaStore.media.genre" :key="index">
                            {{ gen }}
                        </span>
                    </div>

                    <p class="desc-film text-white">
                        {{ mediaStore.media.description }}
                    </p>

                    <div class="d-flex align-items-center">
                        <div
                            @click="favoritesStore.pushFavorites(userStore.account._id, mediaStore.media._id, userStore.account.token)">
                            <font-awesome-icon :icon="['fas', 'heart']" class="font-favorites mr-3"
                                v-if="userStore.account != null" />
                        </div>
                        <router-link :to="{ name: 'watching', params: { id: mediaStore.media._id } }">
                            <button>
                                <font-awesome-icon :icon="['fas', 'play']" />
                                <span class="mr-2"></span>
                                Watch now
                            </button>
                        </router-link>
                    </div>
                </div>
            </div>
        </div>

        <div class="container mt-4">
            <div class="list-casts">
                <div class="row mb-0">
                    <div class="categories col-12">
                        <h4 class="title-menu">
                            CASTS
                            <span class="separate"></span>
                        </h4>
                    </div>
                </div>

                <div class="sections row casts">
                    <template v-for="(cast, index) in mediaStore.media.casts" :key="index">
                        <div class="card cast-item col-5 col-lg-2">
                            <div class="header-img">
                                <img class="card-img-top h-100" :src="cast.avatar" alt="casts-image" />
                            </div>

                            <div class="card-footer">
                                <h6 class="card-title">{{ cast.name }}</h6>
                                <span class="card-text">{{ cast.character }}</span>
                            </div>
                        </div>
                    </template>
                </div>
            </div>

            <Carousel />
        </div>

        <Review :key="reviewStore.reviewsMedia.length" />
    </div>
</template>

<script>
import RatingCircle from '@/components/RatingCircle.vue';
import Carousel from '@/components/Carousel.vue';
import Review from '@/components/Review.vue';

import mediaService from '@/services/media.service.js';
import reviewService from '@/services/review.service.js';
import favoritesService from '@/services/favorites.service.js';

import { useMediaStore } from '@/stores/media.js';
import { useUserStore } from '@/stores/user.js';
import { useFavoritesStore } from '@/stores/favorites.js';
import { useReviewStore } from '@/stores/reviews.js'


export default {
    components: { RatingCircle, Carousel, Review },
    setup() {
        const mediaStore = useMediaStore();
        const userStore = useUserStore();
        const favoritesStore = useFavoritesStore();
        const reviewStore = useReviewStore();
        return {
            mediaStore,
            userStore,
            reviewStore,
            favoritesStore
        }
    },

    methods: {
        async handleSetValue() {
            const reqId = this.$route.params.id;
            if (reqId) {
                this.mediaStore.media = await mediaService.getDetail(reqId);
            }
            else this.mediaStore.media = await mediaService.getRandMovie(reqId);
            this.reviewStore.reviewsMedia = await reviewService.getReviewsMedia(this.mediaStore.media._id);

            if (this.userStore.isLoggedin) {
                const token = await this.userStore.account.token;
                this.favoritesStore.favorites = await favoritesService.getList(token);
                await this.favoritesStore.markFavorited(this.mediaStore.media._id);
            }
        },

        generateKey(item, index) {
            const uniqueKey = `${item}-${index}`;
            return uniqueKey;
        }
    },

    async created() {
        await this.handleSetValue();
        document.getElementsByClassName('background-img-intro')[0].style.backgroundImage =
            'url(' + this.mediaStore.media.posters[0] + ')';
    },
}
</script>

<style lang="scss" scoped>
@import '@/assets/styles/detailMedia.scss';
</style>