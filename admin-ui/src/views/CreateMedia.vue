<template>
    <div class="create-media">
        <div class="container my-4">
            <div class="categories">
                <h4 class="col-md-12 title-menu text-uppercase">
                    Create media
                    <span class="separate"></span>
                </h4>
            </div>

            <form method="POST" class="text-light" @submit.prevent="handleSubmitMedia">
                <div class="form-group row">
                    <label class="col-lg-1 col-form-label form-control-label">Creator</label>
                    <div class="col-lg-3">
                        <input class="form-control" type="text" v-model="mediaStore.formMedia.userID" disabled>
                    </div>

                    <label class="col-lg-1 col-form-label form-control-label">Name</label>
                    <div class="col-lg-4">
                        <input class="form-control" type="text" v-model="mediaStore.formMedia.name">
                    </div>

                    <label class="col-lg-1 col-form-label form-control-label">Category</label>

                    <div class="col-lg-2">
                        <select name="category" class="form-control" v-model="mediaStore.formMedia.category">
                            <option>movie</option>
                            <option>tv series</option>
                        </select>
                    </div>

                    <div class="space-empty w-100"></div>

                    <label class="col-lg-1 col-form-label form-control-label">Description</label>
                    <div class="col-lg-11">
                        <textarea class="desc-content w-100" v-model="mediaStore.formMedia.description"> </textarea>
                    </div>
                </div>

                <div class="form-group row">
                    <label class="col-lg-1 col-form-label form-control-label">Year</label>
                    <div class="col-lg-2">
                        <input class="form-control" type="number" v-model="mediaStore.formMedia.year">
                    </div>

                    <div class="space-empty w-100"></div>

                    <label class="col-lg-1 col-form-label form-control-label">Language</label>
                    <div class="col-lg-2">
                        <input class="form-control" type="text" v-model="mediaStore.formMedia.language">
                    </div>
                </div>

                <div class="form-group row genre" v-for="index in mediaStore.formMedia.genre.length ">
                    <label class="col-lg-1 col-form-label form-control-label">Genre</label>
                    <div class="col-lg-2">
                        <select name="genre" class="form-control" v-model="mediaStore.formMedia.genre[index - 1]">
                            <option v-for="opt in mediaStore.optionGenre">{{ opt }}</option>
                        </select>
                    </div>
                    <BtnAddRemoveItem :msg="msgIdentifyAddDelItem[0]" v-if="index == 1" />
                </div>

                <div class="form-group row episodes" v-for="index in mediaStore.formMedia.eppisodes.length " :key="index">
                    <label class="col-lg-1 col-form-label form-control-label">Ep {{ index }}</label>
                    <div class="col-lg-5">
                        <input class="form-control" type="url" v-model="mediaStore.formMedia.eppisodes[index - 1].videoUrl">
                        <label class="col-form-label form-control-label text-secondary">Video url</label>
                    </div>

                    <BtnAddRemoveItem :msg="msgIdentifyAddDelItem[1]" v-if="index == 1" />
                </div>

                <div class="form-group row cast" v-for="index in mediaStore.formMedia.casts.length" :key="index">
                    <label class="col-lg-1 col-form-label form-control-label">Cast</label>
                    <div class="col-lg-3">
                        <input class="form-control" type="text" v-model="mediaStore.formMedia.casts[index - 1].name">
                        <label class="col-form-label form-control-label text-secondary">Name</label>
                    </div>
                    <div class="col-lg-3">
                        <input class="form-control" type="text" v-model="mediaStore.formMedia.casts[index - 1].character">
                        <label class="col-form-label form-control-label text-secondary">Portray</label>
                    </div>
                    <div class="col-lg-4">
                        <input class="form-control" type="url" v-model="mediaStore.formMedia.casts[index - 1].avatar">
                        <label class="col-form-label form-control-label text-secondary">Image url</label>
                    </div>

                    <BtnAddRemoveItem :msg="msgIdentifyAddDelItem[2]" v-if="index == 1" />
                </div>

                <div class="form-group row">
                    <label class="col-lg-1 col-form-label form-control-label">
                        Images
                    </label>

                    <BtnAddRemoveItem :msg="msgIdentifyAddDelItem[3]" />

                    <div class="space-empty w-100"></div>

                    <label class="col-lg-1 col-form-label form-control-label">Background</label>
                    <div class="col-lg-5">
                        <input class="form-control" type="url" v-model="mediaStore.formMedia.posters[0]">
                    </div>

                    <label class="col-lg-1 col-form-label form-control-label">Poster</label>
                    <div class="col-lg-5">
                        <input class="form-control" type="url" v-model="mediaStore.formMedia.posters[1]">
                    </div>
                </div>

                <div class="form-group row carousel" v-for="img in (mediaStore.formMedia.posters.length - 2)">
                    <label class="col-lg-1 col-form-label form-control-label">Carousel {{ img }}</label>
                    <div class="col-lg-5">
                        <input class="form-control" type="url" v-model="mediaStore.formMedia.posters[img + 1]">
                    </div>
                </div>

                <div class="form-group row">
                    <label class="col-lg-3 col-form-label form-control-label"></label>
                    <div class="col-lg-9 d-flex justify-content-end">
                        <input type="reset" class="btn btn-secondary mr-2" value="Cancel">
                        <input type="submit" class="btn btn-primary" value="Submit">
                    </div>
                </div>
            </form>
        </div>
    </div>
</template>
<script>
import BtnAddRemoveItem from '@/components/BtnAddRemoveItem.vue';

import { useMediaStore } from '@/stores/media.js';
import { useUserStore } from '@/stores/user.js';

import mediaService from '@/services/media.service.js';

export default {
    setup() {
        const mediaStore = useMediaStore();
        const userStore = useUserStore();
        return {
            mediaStore,
            userStore
        }
    },
    components: { BtnAddRemoveItem },

    data() {
        return {
            msgIdentifyAddDelItem: ['genre', 'ep', 'cast', 'img'],
        }
    },

    methods: {
        async handleSubmitMedia() {
            const res = await mediaService.create(this.mediaStore.formMedia, this.userStore.admin.token);
            if (res.status == 201) {
                window.alert('Add movie successfully!');
                this.mediaStore.formMedia = {
                    userID: '', name: '', description: '',
                    posters: [
                        '',
                        '',
                    ],
                    category: '',
                    genre: [
                        ''
                    ],
                    language: '', year: 1999,
                    eppisodes: [
                        {
                            videoUrl: '',
                            number: 1
                        }
                    ],
                    rate: 0, numberRater: 0,
                    casts: [
                        {
                            "name": "",
                            "character": "",
                            "avatar": ""
                        }
                    ]
                }
            }
            else {
                window.alert('Oops! Something wrong');
            }
        }
    },

    async created() {
        this.mediaStore.formMedia.userID = this.userStore.admin._id;
    }
}
</script>
<style lang="scss" scoped>
@import '@/assets/styles/editMedia.scss';
</style>