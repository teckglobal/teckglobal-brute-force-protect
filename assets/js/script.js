console.log('script.js loaded');
console.log('Leaflet available:', typeof L !== 'undefined' ? 'Yes' : 'No');

document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('map')) {
        console.log('Map container found, initializing...');

        // Check for teckglobal_bfp_ajax and use fallback if undefined
        let imagePath;
        if (typeof teckglobal_bfp_ajax !== 'undefined' && teckglobal_bfp_ajax.image_path) {
            imagePath = teckglobal_bfp_ajax.image_path;
        } else {
            console.warn('teckglobal_bfp_ajax is not defined; using fallback image path');
            imagePath = '/wp-content/plugins/teckglobal-brute-force-protect/assets/css/images/';
        }

        const customIcon = L.icon({
            iconUrl: imagePath + 'marker-icon.png',
            iconRetinaUrl: imagePath + 'marker-icon-2x.png',
            shadowUrl: imagePath + 'marker-shadow.png',
            iconSize: [25, 41],
            iconAnchor: [12, 41],
            popupAnchor: [1, -34],
            shadowSize: [41, 41]
        });
        console.log('Icon URLs set:', {
            iconUrl: imagePath + 'marker-icon.png',
            iconRetinaUrl: imagePath + 'marker-icon-2x.png',
            shadowUrl: imagePath + 'marker-shadow.png'
        });

        var map = L.map('map').setView([51.505, -0.09], 2);
        console.log('Map initialized at [51.505, -0.09], zoom 2');

        var aerialLayer = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
        }).addTo(map);
        console.log('Aerial layer added');

        var terrainLayer = L.tileLayer('https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png', {
            attribution: '© <a href="https://opentopomap.org">OpenTopoMap</a> contributors'
        });

        var baseLayers = {
            "Aerial": aerialLayer,
            "Terrain": terrainLayer
        };
        L.control.layers(baseLayers).addTo(map);
        console.log('Layer control added');

        var locationsData = typeof locations !== 'undefined' && locations.length > 0 ? locations : [
            { lat: 51.505, lng: -0.09, ip: 'Test IP', country: 'Test Country' }
        ];
        console.log('Using locations:', locationsData);

        var markers = {};
        locationsData.forEach(function(location) {
            if (location.lat && location.lng) {
                var marker = L.marker([location.lat, location.lng], { icon: customIcon }).addTo(map);
                marker.bindPopup("<b>IP:</b> " + location.ip + "<br><b>Country:</b> " + location.country);
                markers[location.ip] = marker;
                console.log('Marker added for IP:', location.ip, 'at', location.lat, location.lng);
            } else {
                console.warn('Invalid location data:', location);
            }
        });

        document.querySelectorAll('.teckglobal-unban-ip').forEach(function(button) {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                var ip = this.getAttribute('data-ip');

                if (typeof teckglobal_bfp_ajax === 'undefined') {
                    console.error('teckglobal_bfp_ajax not defined; AJAX unban disabled');
                    return;
                }

                jQuery.ajax({
                    url: teckglobal_bfp_ajax.ajax_url,
                    type: 'POST',
                    data: {
                        action: 'teckglobal_bfp_unban_ip',
                        nonce: teckglobal_bfp_ajax.nonce,
                        ip: ip
                    },
                    success: function(response) {
                        if (response.success) {
                            if (markers[ip]) {
                                map.removeLayer(markers[ip]);
                                delete markers[ip];
                                console.log('Marker removed for IP: ' + ip);
                            }
                            var row = button.closest('tr');
                            row.querySelector('td:nth-child(4)').textContent = 'No';
                            row.querySelector('td:nth-child(5)').textContent = 'N/A';
                            row.querySelector('td:nth-child(7)').textContent = 'No';
                            row.querySelector('td:nth-child(8)').textContent = 'No';
                            row.querySelector('td:nth-child(9)').textContent = 'No';
                            row.querySelector('td:nth-child(10)').innerHTML = 'N/A';
                        } else {
                            console.error('Unban failed:', response.data.message);
                        }
                    },
                    error: function(xhr, status, error) {
                        console.error('AJAX error:', error);
                    }
                });
            });
        });
    } else {
        console.error('Map element not found.');
    }
});
