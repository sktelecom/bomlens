/* 헤더의 사이트명(BomLens)을 클릭해도 로고처럼 홈으로 이동시킨다.
 * Material 테마는 로고 이미지에만 링크를 걸기 때문에, 로고 링크의 href를
 * 그대로 재사용해 현재 언어(ko/en)의 홈으로 보낸다. */
document.addEventListener("DOMContentLoaded", function () {
  var logo = document.querySelector(".md-header .md-logo");
  var title = document.querySelector(".md-header__title");
  if (!logo || !title) return;
  title.style.cursor = "pointer";
  title.setAttribute("role", "link");
  title.setAttribute("tabindex", "0");
  function goHome() { window.location.href = logo.href; }
  title.addEventListener("click", goHome);
  title.addEventListener("keydown", function (e) {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); goHome(); }
  });
});
