<template>
    <div class="change-password">
        <div class="container-fluid">
            <form role="form" class="form text-light w-100" method="POST" @submit.prevent="userStore.changePassword()">
                <img src="@/assets/images/logo-red-wolf.png" class="logo" alt="logo">

                <div style="border-top: 5px solid rgb(255, 0, 0)"></div>

                <div class="form-group row py-2">
                    <label class="col-4 col-form-label form-control-label">Current Password</label>
                    <div class="col-8">
                        <input class="form-control" type="password" v-model="userStore.formChangePwd.oldPassword">
                    </div>
                </div>
                <div class="form-group row py-2">
                    <label class="col-4 col-form-label form-control-label">New Password</label>
                    <div class="col-8">
                        <input class="form-control" type="password" v-model="userStore.formChangePwd.newPassword">
                    </div>
                </div>
                <div class="form-group row py-2">
                    <label class="col-4 col-form-label form-control-label">Re-enter Password</label>
                    <div class="col-8">
                        <input class="form-control" type="password" v-model="userStore.formChangePwd.reEnterPassword">
                    </div>
                </div>

                <div class="form-group row">
                    <label class="col-4 col-form-label form-control-label"></label>
                    <div class="col-8 d-flex justify-content-end">
                        <input type="reset" class="btn btn-secondary mr-2" value="Cancel">
                        <input type="submit" class="btn btn-primary" value="Save Changes">
                    </div>
                </div>
            </form>
        </div>
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
    }
}
</script>
<style lang="scss" scoped>
@import '@/assets/styles/globalStyle.scss';

.change-password {
    width: 50%;
    display: block;
    margin: 1.5rem auto;

    .logo {
        width: 30%;
        display: block;
        margin: 1rem auto;
    }
}

@media only screen and (max-width: 739px) {
    .change-password {
        width: 100%;
    }
}
</style>