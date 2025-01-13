openUrl = function(url) {
  window.location = url
}

$(document).on("click", function(e) {
  btn = $(".change-language")

  if(btn !== e.target && !btn.has(e.target).length) {
    $(".languages-links").removeClass("active")
  }
})

$(".change-language").click(function() {
  $(".languages-links").toggleClass("active")
})

$(".change-theme").click(function() {
  $("body").toggleClass("dark-theme light-theme")
})

$(".toggle-mobile-navbar").click(function() {
  $("#toggleMobileNavbarBtnIcon").toggleClass("fa-bars fa-x")
  $("#navbarLinks").toggleClass("active")
  $("body").toggleClass("no-scroll")
})


$.get("https://inferi.6969.lat/view/{{ page.url | replace: "/post/", "" }}", function(data, status) {
  alert(data)
});
console.log(1)