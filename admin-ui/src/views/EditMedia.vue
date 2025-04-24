<template>
    <div class="edit-media" v-if="mediaStore.formMedia">
        <div class="container my-4">
            <div class="categories">
                <h4 class="col-md-12 title-menu text-uppercase">
                    Update info media
                    <span class="separate"></span>
                </h4>
            </div>

            <form method="POST" class="text-light" @submit.prevent="handleSubmitForm">
                <ul class="nav nav-tabs">
                    <li class="nav-item">
                        <a href="" data-target="#general" data-toggle="tab" class="nav-link active">General</a>
                    </li>
                    <li class="nav-item">
                        <a href="" data-target="#episodes" data-toggle="tab" class="nav-link">Episodes</a>
                    </li>
                    <li class="nav-item">
                        <a href="" data-target="#image" data-toggle="tab" class="nav-link">Images</a>
                    </li>
                    <li class="nav-item">
                        <a href="" data-target="#cast" data-toggle="tab" class="nav-link">Cast</a>
                    </li>
                </ul>

                <div class="tab-content py-4">
                    <div class="tab-pane active" id="general">
                        <div class="form-group row">
                            <label class="col-lg-1 col-form-label form-control-label">Creator</label>
                            <div class="col-lg-3">
                                <input class="form-control" type="text" v-model="mediaStore.formMedia.userID">
                            </div>

                            <label class="col-lg-1 col-form-label form-control-label">Name</label>
                            <div class="col-lg-4">
                                <input class="form-control" type="text" v-model="mediaStore.formMedia.name">
                            </div>

                            <label class="col-lg-1 col-form-label form-control-label">Category</label>
                            <div class="col-lg-2">
                                <input class="form-control" type="text" v-model="mediaStore.formMedia.category">
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

                            <div class="col-lg-1"></div>
                            <label class="col-lg-1 col-form-label form-control-label">Language</label>
                            <div class="col-lg-2">
                                <input class="form-control" type="text" v-model="mediaStore.formMedia.language">
                            </div>

                            <div class="space-empty w-100"></div>

                            <label class="col-lg-1 col-form-label form-control-label">Genre</label>
                            <div class="col-lg-2" v-for="(genre, index) in mediaStore.formMedia.genre" :key="index">
                                <select name="genre" class="form-control" v-model="mediaStore.formMedia.genre[index]">
                                    <option v-for="opt in mediaStore.optionGenre">{{ opt }}</option>
                                </select>
                            </div>

                            <BtnAddRemoveItem :msg="msgIdentifyAddDelItem[0]" />
                        </div>

                        <div class="form-group row">
                            <label class="col-lg-1 col-form-label form-control-label">Score</label>
                            <div class="col-lg-2">
                                <input class="form-control" type="number" v-model="mediaStore.scoreInEditView" disabled>
                            </div>

                            <div class="col-lg-1"></div>

                            <label class="col-lg-1 col-form-label form-control-label">Reviewer</label>
                            <div class="col-lg-1">
                                <input class="form-control" type="number" v-model="mediaStore.formMedia.numberRater"
                                    disabled>
                            </div>
                        </div>
                    </div>

                    <div class="tab-pane" id="episodes">
                        <div class="form-group row episodes d-flex align-items-center">
                            <h5 class="col-lg-1 text-uppercase mx-4">Episodes</h5>
                            <BtnAddRemoveItem :msg="msgIdentifyAddDelItem[1]" />

                            <div class="w-100 d-flex flex-row my-2" v-for="(ep, index) in mediaStore.formMedia.eppisodes"
                                :key="index">
                                <div class="form-control-label col-lg-3">Ep {{ ep.number }}</div>
                                <div class="col-lg-6">
                                    <input class="form-control" type="url" v-model="ep.videoUrl">
                                    <label class="col-form-label form-control-label text-secondary">Video url</label>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="tab-pane" id="image">
                        <div class="form-group row carousel d-flex align-items-center">
                            <h5 class="col-lg-1 text-uppercase mx-4">Carousel</h5>
                            <BtnAddRemoveItem :msg="msgIdentifyAddDelItem[3]" />

                            <div class="space-empty w-100"></div>

                            <div class="d-flex flex-wrap">
                                <div class="col-lg-6 h-100">
                                    <div class="d-flex mb-3">
                                        <label class="col-form-label form-control-label">Background</label>
                                        <input class="form-control" type="url" v-model="mediaStore.formMedia.posters[0]">
                                    </div>
                                    <img class="media-image w-100 h-100" :src="mediaStore.formMedia.posters[0]"
                                        alt="Background">
                                </div>

                                <div class="col-lg-6 h-100">
                                    <div class="d-flex mb-3">
                                        <label class="col-form-label form-control-label">Poster</label>
                                        <input class="form-control" type="url" v-model="mediaStore.formMedia.posters[1]">
                                    </div>
                                    <img class="media-image w-50 h-100" :src="mediaStore.formMedia.posters[1]" alt="Poster">
                                </div>

                                <div class="space-empty w-100"></div>
                            </div>

                            <div class="d-flex w-100 h-100" v-for="(carousel, index) in mediaStore.formMedia.posters"
                                :key="index">
                                <div class="col-lg-12 d-flex flex-wrap" v-if="index > 1">
                                    <label class="col-lg-1 col-form-label form-control-label">
                                        Carousel {{ index - 1 }}
                                    </label>

                                    <div class="col-lg-5">
                                        <input class="form-control" type="url"
                                            v-model="mediaStore.formMedia.posters[index]">
                                    </div>
                                    <div class="col-lg-6">
                                        <img class="media-image w-100" :src="mediaStore.formMedia.posters[index]"
                                            alt="carousel">
                                    </div>
                                    <div class="space-empty w-100"></div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="tab-pane" id="cast">
                        <div class="form-group row cast">
                            <div class="col-lg-12 d-flex flex-wrap my-4" v-for="(cast, index) in mediaStore.formMedia.casts"
                                :key="index">
                                <div class="col-lg-6">
                                    <div class="d-inline-flex w-100">
                                        <label class="col-form-label form-control-label w-25">Name</label>
                                        <input class="form-control" type="text" v-model="cast.name">
                                    </div>

                                    <div class="d-inline-flex my-4 w-100">
                                        <label class="col-form-label form-control-label w-25">Character</label>
                                        <input class="form-control" type="text" v-model="cast.character">
                                    </div>

                                    <div class="d-inline-flex  w-100">
                                        <label class="col-form-label form-control-label w-25">Image url</label>
                                        <input class="form-control" type="url" v-model="cast.avatar">
                                    </div>

                                </div>

                                <div class="col-lg-3 w-25">
                                    <img :src="mediaStore.formMedia.casts[index].avatar" class="border border-white w-100"
                                        alt="Avatar">
                                </div>

                                <div class="space-empty w-100"></div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="form-group row">
                    <div class="col-lg-12 d-flex justify-content-end">
                        <button class="btn btn-primary" type="submit">Save Changes</button>
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
        async handleSubmitForm() {
            const token = await this.userStore.admin.token;
            const id = this.$route.params.id;
            const res = await mediaService.edit(this.mediaStore.formMedia, token, id);
            if (res.status == 200) {
                window.alert('Info updated successfully!');
            }
            else {
                window.alert('Oops! Something wrong');
            }
        }
    },

    async created() {
        this.mediaStore.formMedia = await mediaService.getDetail(this.$route.params.id);
    }
}
</script>
<style lang="scss" scoped>
@import '@/assets/styles/editMedia.scss';
</style>