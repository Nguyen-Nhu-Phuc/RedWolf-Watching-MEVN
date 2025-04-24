<template>
    <div class="detail-reviews d-flex flex-wrap container mt-4" v-if="list !== null">
        <div class="card mb-3 mr-3" style="max-width: calc(50% - 1rem); max-height: 50%;" v-for="(item, index) in list"
            :key="index">
            <div class="row no-gutters h-100">
                <div class="col-md-4">
                    <img :src="item.mediaID.posters[1]" alt="poster" class="img-fluid">
                </div>
                <div class="col-md-8">
                    <div class="card-body">
                        <div>
                            <h5 class="card-title">{{ item.mediaID.name }}</h5>
                            <p class="card-text">Review date: {{ item.date.split('T')[0] }}</p>
                            <p class="card-text">
                                Rate:
                                <font-awesome-icon :icon="['fas', 'trophy']" class="text-warning" />
                                {{ item.rate }} / 100
                            </p>
                        </div>
                        <p class="content">
                            Content: {{ item.content }}
                        </p>

                        <p class="mt-3">
                            <strong>Deleted:</strong>
                            {{ item.deleted ? item.deletedAt : 'NO' }}
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>
<script>
import { useReviewStore } from '@/stores/review.js';
import { useUserStore } from '@/stores/user.js';

export default {
    setup() {
        const reviewStore = useReviewStore();
        const userStore = useUserStore();
        return {
            reviewStore,
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
        this.list = await this.reviewStore.detailReviewsUser(token, userId);
    }
}
</script>
<style lang="scss" scoped>
.content {
    margin-bottom: 0;
    margin-top: 8px;
    text-align: justify;
}
</style>