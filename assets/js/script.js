jQuery(document).ready(function($) {
    // Initialize Google Map
    function initMap() {
        var map = new google.maps.Map(document.getElementById('map'), {
            zoom: 2,
            center: {lat: 0, lng: 0}
        });

        locations.forEach(function(location) {
            var count = parseInt(location.count);
            var color = count >= 26 ? 'red' : count >= 11 ? 'orange' : 'green';
            var marker = new google.maps.Marker({
                position: {lat: parseFloat(location.latitude), lng: parseFloat(location.longitude)},
                map: map,
                icon: {
                    path: google.maps.SymbolPath.CIRCLE,
                    scale: 8,
                    fillColor: color,
                    fillOpacity: 0.8,
                    strokeWeight: 1
                },
                title: `${location.ip} (${location.country}, Count: ${count})`
            });
        });
    }

    if (typeof locations !== 'undefined') {
        initMap();
    }
});
