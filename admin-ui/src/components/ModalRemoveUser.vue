<template>
    <div class="modal fade" id="remove-user-modal" tabindex="-1" role="dialog" aria-labelledby="exampleModalCenterTitle"
        aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="exampleModalLongTitle">Delete member?</h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <div class="modal-body">
                    Are you sure to delete this member?
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-danger" @click="handleDelete()">
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
import userService from '@/services/user.service.js';

export default {
    props: ['id'],

    setup() {
        const userStore = useUserStore();
        return {
            userStore,
        }
    },

    methods: {
        async handleSetData() {
            this.userStore.members = await userService.list(this.userStore.admin.token);
        },

        async handleDelete() {
            const res = await this.userStore.deleteMember(this.userStore.admin.token, this.id);
            if (res.status == 200) {
                $('#remove-user-modal').modal('hide');
                $('.modal-backdrop').remove();
                await this.handleSetData();
            }
        }
    }
}
</script>

<style lang="scss" scoped></style>
