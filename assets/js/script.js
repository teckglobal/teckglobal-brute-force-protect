document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('map') && typeof locations !== 'undefined') {
        var map = L.map('map').setView([51.505, -0.09], 2); // Default center (world view)
        var markers = {};

        var aerialLayer = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
        }).addTo(map);

        var terrainLayer = L.tileLayer('https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png', {
            attribution: '© <a href="https://opentopomap.org">OpenTopoMap</a> contributors'
        });

        var baseLayers = {
            "Aerial": aerialLayer,
            "Terrain": terrainLayer
        };
        L.control.layers(baseLayers).addTo(map);

        locations.forEach(function(location) {
            var marker = L.marker([location.lat, location.lng]).addTo(map);
            marker.bindPopup("<b>IP:</b> " + location.ip + "<br><b>Country:</b> " + location.country);
            markers[location.ip] = marker;
        });

        document.querySelectorAll('.teckglobal-unban-ip').forEach(function(button) {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                var ip = this.getAttribute('data-ip');
                var url = this.getAttribute('href');

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
                            row.querySelector('td:nth-child(4)').textContent = 'No'; // Banned column
                            row.querySelector('td:nth-child(5)').textContent = 'N/A'; // Ban Expiry column
                            row.querySelector('td:nth-child(7)').textContent = 'No'; // Scan Exploit column
                            row.querySelector('td:nth-child(8)').textContent = 'No'; // Brute Force column
                            row.querySelector('td:nth-child(9)').textContent = 'No'; // Manual Ban column
                            row.querySelector('td:nth-child(10)').innerHTML = 'N/A'; // Action column
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
        console.log('Map element or locations data not found.');
    }
});
