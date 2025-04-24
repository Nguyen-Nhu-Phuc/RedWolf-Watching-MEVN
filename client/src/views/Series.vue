<template>
    <div class="series"
        v-if="mediaStore.media && mediaStore.popularTVSeries.length > 0 && mediaStore.ratedSeries.length > 0">
        <MovieIntro :key="mediaStore.media._id" />

        <div class="container">
            <div class="row stored-series">
                <div class="col-md-12 categories">
                    <div>
                        <h4 class="title-menu">
                            LIST SERIES
                            <span class="separate"></span>
                        </h4>
                    </div>

                    <ul class="nav nav-tabs">
                        <li class="nav-item">
                            <button class="btn-transfer-mode text-uppercase text-white rounded-0 active" aria-current="page"
                                data-target="#popular" data-toggle="tab">Popular</button>
                        </li>
                        <li class="nav-item">
                            <button class="btn-transfer-mode text-uppercase text-white rounded-0" data-target="#rated"
                                data-toggle="tab">Rated</button>
                        </li>
                    </ul>
                </div>

                <div class="tab-content">
                    <div class="tab-pane active" id="popular">
                        <div class="sections row list">
                            <template
                                v-for="(film, idx) in mediaStore.popularTVSeries.slice(paginationStore.indexFirstFilmOfPage(paginationStore.idxCurPage), paginationStore.indexLastFilmOfPage(paginationStore.idxCurPage) + 1)"
                                :key="idx">
                                <div class="list-item col-4 col-md-3 p-2 mb-2">
                                    <router-link :to="{ name: 'detail', params: { id: film._id } }">
                                        <div class="card h-100">
                                            <img class="card-img-top h-100" :src="film.posters[1]" alt="Card image cap" />

                                            <div class="card-body">
                                                <div class="empty-space"></div>
                                                <div>
                                                    <h4 class="card-title">{{ film.name }}</h4>
                                                    <p class="card-text">{{ film.year }}</p>
                                                </div>
                                            </div>
                                        </div>
                                    </router-link>
                                </div>
                            </template>
                        </div>
                    </div>

                    <div class="tab-pane" id="rated">
                        <div class="sections row list">
                            <template
                                v-for="(film, idx) in mediaStore.ratedSeries.slice(paginationStore.indexFirstFilmOfPage(paginationStore.idxCurPage), paginationStore.indexLastFilmOfPage(paginationStore.idxCurPage) + 1)"
                                :key="idx">
                                <div class="list-item col-4 col-md-3 p-2 mb-2">
                                    <router-link :to="{ name: 'detail', params: { id: film._id } }">
                                        <div class="card h-100">
                                            <img class="card-img-top h-100" :src="film.posters[1]" alt="Card image cap" />

                                            <div class="card-body">
                                                <div class="empty-space"></div>
                                                <div>
                                                    <h4 class="card-title">{{ film.name }}</h4>
                                                    <p class="card-text">{{ film.year }}</p>
                                                </div>
                                            </div>
                                        </div>
                                    </router-link>
                                </div>
                            </template>
                        </div>
                    </div>
                </div>

            </div>

            <Pagination :totalQuantityMovies="mediaStore.popularTVSeries.length" :key="paginationStore.idxCurPage" />
        </div>
    </div>
</template>

<script>
import MovieIntro from '@/components/MovieIntro.vue';
import Pagination from '@/components/Pagination.vue';

import mediaService from '@/services/media.service.js';
import { useMediaStore } from '@/stores/media.js';
import { usePaginationStore } from '@/stores/pagination.js';

export default {
    components: { MovieIntro, Pagination },

    setup() {
        const mediaStore = useMediaStore();
        const paginationStore = usePaginationStore();
        return {
            mediaStore,
            paginationStore
        }
    },

    methods: {
        async handleSetData() {
            const reqId = this.$route.params.id;
            if (reqId) {
                this.mediaStore.media = await mediaService.getDetail(reqId);
            }
            else this.mediaStore.media = await mediaService.getRandSeries(reqId);
        }
    },

    async created() {
        await this.handleSetData();
    }
}

</script>

<style lang="scss" scoped>
.nav-tabs {
    border: none;
}
</style>
