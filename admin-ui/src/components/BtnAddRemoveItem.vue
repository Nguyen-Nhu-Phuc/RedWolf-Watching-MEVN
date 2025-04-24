<template>
    <div class="d-flex col-lg-1 text-center">
        <font-awesome-icon :icon="['fas', 'plus-circle']" class="btn-add-item h3 mt-1" @click="handleAdd" />
        <font-awesome-icon :icon="['fas', 'minus-circle']" class="btn-del-item h3 mt-1 ml-3" @click="handleDel" />
    </div>
</template>
<script>
import { useMediaStore } from '@/stores/media.js';

export default {
    props: ['msg'],
    setup() {
        const mediaStore = useMediaStore();
        return {
            mediaStore
        }
    },

    methods: {
        handleAdd() {
            if (this.msg === 'genre') {
                this.mediaStore.formMedia.genre.push("");
            }
            else if (this.msg === 'ep') {
                const number = this.mediaStore.formMedia.eppisodes.length + 1;
                this.mediaStore.formMedia.eppisodes.push({
                    videoUrl: '',
                    number: number
                });
            }
            else if (this.msg === 'cast') {
                this.mediaStore.formMedia.casts.push({
                    name: '',
                    character: '',
                    avatar: ''
                });
            }
            else {
                this.mediaStore.formMedia.posters.push("");
            }
        },

        handleDel() {
            if (this.msg === 'genre') {
                this.mediaStore.formMedia.genre.pop();
            }
            else if (this.msg === 'ep') {
                this.mediaStore.formMedia.eppisodes.pop();
            }
            else if (this.msg === 'cast') {
                this.mediaStore.formMedia.casts.pop();
            }
            else {
                this.mediaStore.formMedia.posters.pop();
            }
        }
    }
}
</script>
<style lang="scss" scoped>
@import '@/assets/styles/globalStyle.scss';

.btn-add-item,
.btn-del-item {
    cursor: pointer;
}

.btn-add-item {
    color: $blue-color;
}

.btn-del-item {
    color: $primary-color;
}
</style>