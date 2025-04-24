<template>
    <div class="search" v-if="mediaStore.popularMovies.length > 0 && mediaStore.popularTVSeries.length > 0">
        <div class="container my-4">
            <div class="input-group">
                <div class="form-outline">
                    <input type="search" id="search-media" class="form-control search-input"
                        placeholder="Search: name movie" v-model="search" />
                </div>
                <button type="button" class="btn btn-search text-white">
                    <i class="fas fa-search"></i>
                </button>
            </div>

            <div class="search-result">
                <div class="sections row list" v-if="filtersMedia">
                    <template v-for="(item, index) in filtersMedia.slice(16).length" :key="index">
                        <div class="list-item col-4 col-md-3 p-1 mb-1">
                            <router-link :to="{ name: 'detail', params: { id: filtersMedia[index]._id } }">
                                <div class="card h-100">
                                    <img class="card-img-top h-100" :src="filtersMedia[index].posters[1]" alt="Poster" />

                                    <div class="card-body">
                                        <div class="empty-space"></div>
                                        <div>
                                            <h4 class="card-title">{{ filtersMedia[index].name }}</h4>
                                            <p class="card-text">{{ filtersMedia[index].year }}</p>
                                        </div>
                                    </div>
                                </div>
                            </router-link>
                        </div>
                    </template>

                    <div>
                        <h1 class="text-white" v-if="filtersMedia.length === 0">No result</h1>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>

<script>
import { useMediaStore } from '@/stores/media.js';

export default {
    setup() {
        const mediaStore = useMediaStore();
        return {
            mediaStore
        }
    },

    data() {
        return {
            search: ''
        }
    },

    computed: {
        population() {
            return this.mediaStore.popularMovies.concat(this.mediaStore.popularTVSeries);
        },

        filtersMedia() {
            const result = this.population.filter(item => {
                return item.name.toLowerCase().includes(this.search.toLowerCase());
            });
            return result.sort((a, b) => 0.5 - Math.random());
        },
    },
}
</script>

<style lang="scss" scoped>
.search {
    min-height: 600px;
}

.input-group {
    display: flex;
    justify-content: space-around;

    .form-outline {
        flex: 1;

        .search-input {
            padding-top: 2px;
            padding-bottom: 2px;
            font-size: 1.3rem;
        }
    }
}

.btn-search {
    background-color: $primary-color;
    box-shadow: none;
    outline: none;

    &:hover {
        background-color: $primary-color-impress;
    }
}
</style>