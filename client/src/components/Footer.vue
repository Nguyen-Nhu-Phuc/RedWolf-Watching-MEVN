<template>
    <div class="footer">
        <footer class="font-small">
            <div class="text-center text-md-left">
                <div class="page-footer">
                    <div class="row m-0">
                        <div class="col-12 col-sm-6 mt-md-0 company-communication">
                            <div class="d-flex align-items-center justify-content-center">
                                <img class="logo-footer" src="@/assets/images/logo-red-wolf.png" alt="logo">
                                <h2 class="ml-4 text-danger">REDWOLF CINEMA</h2>
                            </div>
                            <p class="address-company">
                                Toyota Ninh Kieu Building 3rd Floor, 57 Cach Mang Thang Tam Str., Ninh Kieu, Dist, Can Tho
                            </p>
                            <p>
                                <font-awesome-icon :icon="['fas', 'phone']" />
                                Phone: 028 7109 1234
                            </p>
                            <p>
                                <font-awesome-icon :icon="['fas', 'envelope']" />
                                Email: jeetkunedo10000@gmail.com
                            </p>
                        </div>

                        <!-- <hr class="clearfix w-100 d-md-none pb-3"> -->

                        <div class="col-sm-2 mb-3 about-categories text-center">
                            <h5 class="title-item-advertise text-uppercase">Top Genre</h5>
                            <ul class="list-unstyled menu-categories">
                                <li>
                                    <a href="#!">Action</a>
                                </li>
                                <li>
                                    <a href="#!">Drama</a>
                                </li>
                                <li>
                                    <a href="#!">Romance</a>
                                </li>
                                <li>
                                    <a href="#!">Historical</a>
                                </li>
                                <li>
                                    <a href="#!">Fantasy</a>
                                </li>
                            </ul>
                        </div>

                        <div class="col-sm-2 mb-3 about-categories text-center">
                            <h5 class="title-item-advertise text-uppercase">Nation</h5>
                            <ul class="list-unstyled menu-categories">
                                <li>
                                    <a href="#!">United States</a>
                                </li>
                                <li>
                                    <a href="#!">United Kingdom</a>
                                </li>
                                <li>
                                    <a href="#!">Korea</a>
                                </li>
                                <li>
                                    <a href="#!">China</a>
                                </li>
                                <li>
                                    <a href="#!">Japan</a>
                                </li>
                            </ul>
                        </div>

                        <div class="col-sm-2 mb-3 about-company text-center">
                            <h5 class="title-item-advertise text-uppercase">Company</h5>

                            <ul class="list-unstyled menu-company">
                                <li>
                                    <router-link :to="{ name: 'home' }">Home</router-link>
                                </li>
                                <li>
                                    <router-link :to="{ name: 'movies' }">Movies</router-link>
                                </li>
                                <li>
                                    <router-link :to="{ name: 'series' }">Series</router-link>
                                </li>
                                <li>
                                    <a href="#!">Contact Us</a>
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </footer>

        <div class="footer-copyright text-center text-white py-4">© 2023 Copyright:
            <a class="text-copyright" href="/"> DO HIEU NGHIA</a>
        </div>
    </div>
</template>

<script>
export default {

}

</script>

<style lang="scss" scoped>
@import '../assets/styles/footer.scss';
</style>
