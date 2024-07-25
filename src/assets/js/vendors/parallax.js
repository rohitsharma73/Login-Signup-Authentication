// Parallax js

var scenes = document.querySelectorAll(".scene");
var parallaxInstances = [];

scenes.forEach(function (scene) {
    var parallaxInstance = new Parallax(scene);
    parallaxInstances.push(parallaxInstance);
});
