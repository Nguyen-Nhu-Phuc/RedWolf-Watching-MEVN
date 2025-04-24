<template>
    <div class="home" v-if="mediaStore.media &&
        mediaStore.popularMovies.length > 0 && mediaStore.ratedMovies.length > 0 &&
        mediaStore.popularTVSeries.length > 0 && mediaStore.ratedSeries.length > 0">
        <MovieIntro :key="generateKey(mediaStore.media._id, userStore.isLoggedin)" />

        <div class="container">
            <div class="sections row popular-movies">
                <div class="categories col-12">
                    <h4 class="title-menu">
                        POPULAR MOVIES
                        <span class="separate"></span>
                    </h4>
                </div>

                <div class="w-100"></div>

                <div class="list col-12 p-0">
                    <div class="list-item col-3" v-for="(item, index) in  4 " :key="index">
                        <router-link :to="{ name: 'detail', params: { id: mediaStore.popularMovies[index]._id } }">
                            <div class="card h-100">
                                <img class="card-img-top h-100" :src="mediaStore.popularMovies[index].posters[1]"
                                    alt="Poster" />

                                <div class="card-body">
                                    <div class="empty-space"></div>
                                    <div>
                                        <h4 class="card-title">{{ mediaStore.popularMovies[index].name }}</h4>
                                        <p class="card-text">{{ mediaStore.popularMovies[index].year }}</p>
                                    </div>
                                </div>
                            </div>
                        </router-link>
                    </div>
                </div>
            </div>

            <div class="sections row popular-tv-series">
                <div class="categories  col-12">
                    <h4 class="title-menu">
                        POPULAR SERIES
                        <span class="separate"></span>
                    </h4>
                </div>

                <div class="w-100"></div>

                <div class="list col-12  p-0">
                    <div class="list-item  col-3" v-for="( item, index ) in  4 " :key="index">
                        <router-link :to="{ name: 'detail', params: { id: mediaStore.popularTVSeries[index]._id } }">
                            <div class="card h-100">
                                <img class="card-img-top h-100" :src="mediaStore.popularTVSeries[index].posters[1]"
                                    alt="Card image cap" />

                                <div class="card-body">
                                    <div class="empty-space"></div>
                                    <div>
                                        <h4 class="card-title">{{ mediaStore.popularTVSeries[index].name }}</h4>
                                        <p class="card-text">{{ mediaStore.popularTVSeries[index].year }}</p>
                                    </div>
                                </div>
                            </div>
                        </router-link>
                    </div>
                </div>
            </div>

            <div class="sections row rated-movies">
                <div class="categories col-12">
                    <h4 class="title-menu">
                        TOP RATED MOVIES
                        <span class="separate"></span>
                    </h4>
                </div>

                <div class="w-100"></div>

                <div class="list col-12 p-0">
                    <div class="list-item col-3" v-for="( item, index ) in  4 " :key="index">
                        <router-link :to="{ name: 'detail', params: { id: mediaStore.ratedMovies[index]._id } }">
                            <div class="card h-100">
                                <img class="card-img-top h-100" :src="mediaStore.ratedMovies[index].posters[1]"
                                    alt="Card image cap" />

                                <div class="card-body">
                                    <div class="empty-space"></div>
                                    <div>
                                        <h4 class="card-title">{{ mediaStore.ratedMovies[index].name }}</h4>
                                        <p class="card-text">{{ mediaStore.ratedMovies[index].year }}</p>
                                    </div>
                                </div>
                            </div>
                        </router-link>
                    </div>
                </div>
            </div>

            <div class="sections row rated-series">
                <div class="categories col-12">
                    <h4 class="title-menu">
                        TOP RATED SERIES
                        <span class="separate"></span>
                    </h4>
                </div>

                <div class="w-100"></div>

                <div class="list col-12 p-0">
                    <div class="list-item col-3" v-for="( item, index ) in  4 " :key="index">
                        <router-link :to="{ name: 'detail', params: { id: mediaStore.ratedSeries[index]._id } }">
                            <div class="card h-100">
                                <img class="card-img-top h-100" :src="mediaStore.ratedSeries[index].posters[1]"
                                    alt="Card image cap" />

                                <div class="card-body">
                                    <div class="empty-space"></div>
                                    <div>
                                        <h4 class="card-title">{{ mediaStore.ratedSeries[index].name }}</h4>
                                        <p class="card-text">{{ mediaStore.ratedSeries[index].year }}</p>
                                    </div>
                                </div>
                            </div>
                        </router-link>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>

<script>
import MovieIntro from '@/components/MovieIntro.vue';

import { useMediaStore } from '@/stores/media.js';
import { useUserStore } from '@/stores/user.js';

import mediaService from '@/services/media.service.js';


export default {
    setup() {
        const mediaStore = useMediaStore();
        const userStore = useUserStore();
        return {
            userStore,
            mediaStore
        }
    },

    components: { MovieIntro },

    methods: {
        async handleSetData() {
            const reqId = this.$route.params.id;
            if (reqId) {
                this.mediaStore.media = await mediaService.getDetail(reqId);
            }
            else this.mediaStore.media = await mediaService.getRandMovie();
        },

        generateKey(item, index) {
            const uniqueKey = `${item}-${index}`;
            return uniqueKey;
        },
    },

    async created() {
        await this.handleSetData();
    },
};
</script>

<style lang="scss" scoped>
.container {
    margin-top: 32px;
}
</style>
