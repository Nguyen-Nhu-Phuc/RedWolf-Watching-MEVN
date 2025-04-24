<template>
    <div class="membership container-fluid" v-if="userStore.members.length > 0">
        <router-link :to="{ name: 'deleted' }" class="btn btn-danger float-right my-2">
            Trash <font-awesome-icon :icon="['fas', 'trash']" />
        </router-link>
        <table class="table table-bordered bg-light">
            <thead>
                <tr class="text-center">
                    <th scope="col">#</th>
                    <th scope="col" width="28%">Full Name</th>
                    <th scope="col">Username</th>
                    <th scope="col">Favorites</th>
                    <th scope="col">Reviews</th>
                    <th scope="col">Admin Rights</th>
                    <th scope="col" colspan="3"></th>
                </tr>
            </thead>
            <tbody>
                <tr v-for="(user, index) in userStore.members" :key="index" class="text-center items-movie">
                    <th scope="row">{{ index + 1 }}</th>
                    <td class="text-left">{{ user.fullName }}</td>
                    <td>{{ user.username }}</td>
                    <td class="text-info">
                        {{ userStore.members[index].mediaID?.length || 0 }}
                    </td>
                    <td>
                        {{ user.reviews || 0 }}
                    </td>
                    <td class="text-secondary font-weight-bold">
                        {{ user.isAdmin ? 'YES' : 'NO' }}
                    </td>
                    <td colspan="3">
                        <router-link :to="{ name: 'favorites', params: { id: user._id } }"
                            class="btn btn-link text-warning">
                            Favorites
                        </router-link>
                        <router-link :to="{ name: 'reviews', params: { id: user._id } }" class="btn btn-link text-success">
                            Reviews
                        </router-link>
                        <a href="" class="btn btn-link btn-modal text-danger" data-toggle="modal" @click="getId(user._id)"
                            data-target="#remove-user-modal">Delete</a>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>

    <ModalRemoveUser :id="idMember" :key="idMember" />
</template>
<script>
import ModalRemoveUser from '@/components/ModalRemoveUser.vue';

import { useUserStore } from '@/stores/user.js';
import { useFavoriteStore } from '@/stores/favorite.js';
import { useReviewStore } from '@/stores/review.js';

import userService from '@/services/user.service.js';
import favoriteService from '@/services/favorite.service.js';
import reviewService from '@/services/review.service.js';

export default {
    setup() {
        const userStore = useUserStore();
        const favoriteStore = useFavoriteStore();
        const reviewStore = useReviewStore();
        return {
            userStore,
            favoriteStore,
            reviewStore
        }
    },

    components: { ModalRemoveUser },

    data() {
        return {
            idMember: null
        }
    },

    methods: {
        async mergeByUserId() {
            return this.userStore.members.map(itm => ({
                ...this.favoriteStore.favorites.find((item) => (item.userID === itm._id) && item),
                ...this.reviewStore.reviews.find((item) => (item.userID === itm._id) && item),
                ...itm
            }));
        },

        getId(id) {
            this.idMember = id;
        },

        async handleSetData() {
            this.userStore.members = await userService.list(this.userStore.admin.token);
            this.favoriteStore.favorites = await favoriteService.favorites(this.userStore.admin.token);
            this.reviewStore.reviews = await reviewService.reviews(this.userStore.admin.token);
            this.userStore.members = await this.mergeByUserId();
        },
    },

    async created() {
        await this.handleSetData();
    }
}
</script>
<style lang="scss" scoped>
@import '@/assets/styles/globalStyle.scss';
</style>