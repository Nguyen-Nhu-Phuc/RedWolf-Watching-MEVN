<template>
    <div class="membership-trash mt-4 container">
        <h5 class="text-light text-center" v-if="userStore.deletedMembers.length === 0">No member have been deleted</h5>
        <table class="table table-bordered bg-light" v-else>
            <thead>
                <tr class="text-center">
                    <th scope="col">#</th>
                    <th scope="col">Full Name</th>
                    <th scope="col">Username</th>
                    <th scope="col">Admin Rights</th>
                    <th scope="col" colspan="2"></th>
                </tr>
            </thead>
            <tbody>
                <tr v-for="(member, index) in userStore.deletedMembers" :key="index" class="text-center items-member">
                    <th scope="row">{{ index + 1 }}</th>
                    <td class="text-left">{{ member.fullName }}</td>
                    <td class="text-info">{{ member.username }}</td>
                    <td class="text-secondary">{{ member.isAdmin ? 'YES' : 'NO' }}</td>
                    <td colspan="2">
                        <button type="button" class="btn btn-link text-primary"
                            @click="userStore.restoreMember(userStore.admin.token, member._id)">
                            Restore
                        </button>
                        <button type="button" class="btn btn-link text-danger"
                            @click="userStore.forceDel(userStore.admin.token, member._id)">
                            Remove
                        </button>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>
</template>
<script>
import { useUserStore } from '@/stores/user.js';

export default {
    setup() {
        const userStore = useUserStore();
        return {
            userStore
        }
    },

    async created() {
        await this.userStore.getTrash(this.userStore.admin.token);
    },
}
</script>
<style lang="scss" scoped>
.membership-trash {
    min-height: 510px;
}

.btn.btn-link {
    box-shadow: none;
}
</style>