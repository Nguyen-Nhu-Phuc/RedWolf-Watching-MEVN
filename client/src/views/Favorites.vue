<template>
    <div class="favorites" v-if="favoritesStore.favorites">
        <div class="container mt-4">
            <div class="sections row mb-0">
                <div class="categories col-12">
                    <h4 class="title-menu text-uppercase">
                        YOUR favorites
                        <span class="separate"></span>
                    </h4>
                </div>

            </div>

            <div class="list-empty text-center text-light" v-if="favoritesStore.favorites.mediaID.length === 0">
                <h2>You haven't favorited any media yet</h2>
            </div>

            <div class="sections row list mt-0" v-else>
                <template v-for="(media, index) in favoritesStore.favorites.mediaID" :key="index">
                    <div class="list-favorites-item col-4 col-md-3 mb-2">
                        <router-link :to="{ name: 'detail', params: { id: media._id } }">
                            <div class="card mt-2">
                                <img class="card-img-top h-100" :src="media.posters[1]" alt="Poster" />

                                <div class="card-body">
                                    <div class="empty-space"></div>
                                    <div>
                                        <h4 class="card-title">{{ media.name }}</h4>
                                        <p class="card-text">{{ media.year }}</p>
                                    </div>
                                </div>
                            </div>
                        </router-link>

                        <div class="remove" @click="removeMedia(media)">
                            <font-awesome-icon :icon="['fas', 'trash']" class="icon-remove" />
                            <span class="ml-2">Remove</span>
                        </div>
                    </div>
                </template>
            </div>
        </div>
    </div>
</template>

<script>
import { useFavoritesStore } from '@/stores/favorites.js';
import { useUserStore } from '@/stores/user.js';

import favoritesService from '@/services/favorites.service.js';

export default {
    setup() {
        const favoritesStore = useFavoritesStore();
        const userStore = useUserStore();
        return {
            favoritesStore,
            userStore
        }
    },

    methods: {
        async handleSetData() {
            const token = await this.userStore.account.token;
            this.favoritesStore.favorites = await favoritesService.getList(token);
        },

        async removeMedia(media) {
            const id = this.favoritesStore.getMediaIDRemove(media);
            this.favoritesStore.favorites = await favoritesService.remove(id, this.userStore.account.token);
            await this.handleSetData();
        },
    },

    async created() {
        await this.handleSetData();
    },
}
</script>

<style lang="scss" scoped>
@import '@/assets/styles/favorites.scss';

@media only screen and (min-width: 740px) and (max-width: 1023px) {}
</style>