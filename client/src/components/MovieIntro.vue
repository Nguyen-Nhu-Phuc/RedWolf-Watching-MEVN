<template>
    <div class="movie-intro">
        <div class="container-fluid m-0 p-0">
            <div class="background-img-intro"> </div>
            <div class="img-header-desc">
                <h4 class="movie-name">{{ mediaStore.media.name }}</h4>

                <div class="media-rating">
                    <RatingCircle />
                    <span class="mr-4"></span>
                    <span class="genre mr-4" v-for="(gen, index) in mediaStore.media.genre" :key="index">
                        {{ gen }}
                    </span>
                </div>

                <p class="desc-film text-white my-3">
                    {{ mediaStore.media.description }}
                </p>

                <div class="d-flex align-items-center">
                    <div
                        @click="favoritesStore.pushFavorites(userStore.account._id, mediaStore.media._id, userStore.account.token)">
                        <font-awesome-icon :icon="['fas', 'heart']" class="font-favorites mr-3"
                            v-if="userStore.isLoggedin" />
                    </div>

                    <router-link :to="{ name: 'watching', params: { id: mediaStore.media._id } }" class="watch-media-btn">
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
</template>
<script>
import RatingCircle from './RatingCircle.vue';

import { useMediaStore } from '@/stores/media.js';
import { useUserStore } from '@/stores/user.js';
import { useFavoritesStore } from '@/stores/favorites.js';

import favoritesService from '@/services/favorites.service.js';

export default {
    components: { RatingCircle },

    setup() {
        const mediaStore = useMediaStore();
        const userStore = useUserStore();
        const favoritesStore = useFavoritesStore();
        return {
            mediaStore,
            userStore,
            favoritesStore
        }
    },

    methods: {
        async handleSetData() {
            if (this.userStore.isLoggedin) {
                const token = await this.userStore.account.token;
                this.favoritesStore.favorites = await favoritesService.getList(token);
                this.favoritesStore.markFavorited(this.mediaStore.media._id);
            }
        }
    },

    async created() {
        await this.handleSetData();
    },

    async mounted() {
        document.getElementsByClassName('background-img-intro')[0].style.backgroundImage =
            'url(' + this.mediaStore.media.posters[0] + ')';
    },
}
</script>

<style lang="scss" scoped>
@import '@/assets/styles/movieIntro.scss';
</style>
