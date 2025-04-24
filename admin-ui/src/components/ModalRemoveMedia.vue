<template>
    <div class="modal fade" id="remove-media-modal" tabindex="-1" role="dialog" aria-labelledby="exampleModalCenterTitle"
        aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="exampleModalLongTitle">Delete film?</h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <div class="modal-body">
                    Are you sure to delete this movie?
                </div>
                <div class="modal-footer">
                    <button type="button" @click="mediaStore.deleteMedia(userStore.admin.token, this.id)"
                        class="btn btn-danger">
                        Delete
                    </button>
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancel</button>
                </div>
            </div>
        </div>
    </div>
</template>

<script>
import { useUserStore } from '@/stores/user.js';
import { useMediaStore } from '@/stores/media.js';

export default {
    props: ['id'],

    setup() {
        const userStore = useUserStore();
        const mediaStore = useMediaStore();
        return {
            userStore,
            mediaStore
        }
    }
}
</script>

<style lang="scss" scoped></style>
