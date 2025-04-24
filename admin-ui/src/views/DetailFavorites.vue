<template>
    <div class="detail-favorites d-flex flex-wrap container mt-4" v-if="list !== null">
        <div class="card mb-3 mr-3" style="max-width: calc(50% - 1rem);" v-for="(item, index) in list.mediaID" :key="index">
            <div class="row no-gutters h-100">
                <div class="col-md-4">
                    <img :src="item.posters[1]" alt="poster" class="img-fluid h-100">
                </div>
                <div class="col-md-8">
                    <div class="card-body d-flex flex-column justify-content-between h-100">
                        <div>
                            <h5 class="card-title">{{ item.name }}</h5>
                            <p class="card-text">{{ item.year }}</p>
                            <p class="card-text">
                                <font-awesome-icon :icon="['fas', 'trophy']" class="text-warning" />
                                {{ item.rate / item.numberRater }}
                            </p>
                        </div>
                        <p class="font-italic note-creator">Creator: {{ item.userID }}</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>
<script>
import { useFavoriteStore } from '@/stores/favorite.js';
import { useUserStore } from '@/stores/user.js';

export default {
    setup() {
        const favoriteStore = useFavoriteStore();
        const userStore = useUserStore();
        return {
            favoriteStore,
            userStore
        }
    },

    data() {
        return {
            list: null
        }
    },

    async created() {
        const token = await this.userStore.admin.token;
        const userId = this.$route.params.id;
        this.list = await this.favoriteStore.detailFavoritesUser(token, userId);
        console.log(this.list);
    },

}
</script>
<style lang="scss" scoped>
.note-creator {
    margin-bottom: 0;
}
</style>