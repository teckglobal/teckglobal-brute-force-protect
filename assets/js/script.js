console.log('script.js loaded at: ' + new Date().toISOString());

jQuery(document).ready(function($) {
    console.log('jQuery available: ' + (typeof $ !== 'undefined' ? 'Yes' : 'No'));
    console.log('jQuery document.ready fired at: ' + new Date().toISOString());

    var $toggleLinks = $('.teckglobal-bfp-toggle');
    console.log('Initial check found ' + $toggleLinks.length + ' toggle links');
    if ($toggleLinks.length > 0) {
        console.log('First toggle link HTML: ' + $toggleLinks[0].outerHTML);
    } else {
        console.warn('No toggle links found on initial check.');
    }

    $(document).on('click', '.teckglobal-bfp-toggle', function(e) {
        e.preventDefault();
        e.stopImmediatePropagation();
        var $link = $(this);
        var action = $link.attr('data-action');
        var plugin = $link.attr('data-plugin');

        console.log('Toggle clicked at: ' + new Date().toISOString());
        console.log('Action: ' + action + ', Plugin: ' + plugin);
        console.log('Clicked element: ' + $link[0].outerHTML);

        if (typeof teckglobal_bfp_ajax === 'undefined') {
            console.error('teckglobal_bfp_ajax not defined. Check localization.');
            return;
        }

        console.log('teckglobal_bfp_ajax: ' + JSON.stringify(teckglobal_bfp_ajax));

        $link.after('<span class="spinner" style="display:inline-block; margin-left:5px; visibility:visible;"></span>');
        $link.css('pointer-events', 'none');

        $.ajax({
            url: teckglobal_bfp_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'toggle_auto_update_plugin',
                _wpnonce: teckglobal_bfp_ajax.toggle_nonce,
                plugin: plugin,
                toggle_action: action
            },
            beforeSend: function() {
                console.log('Sending AJAX with data: ' + JSON.stringify({
                    action: 'toggle_auto_update_plugin',
                    _wpnonce: teckglobal_bfp_ajax.toggle_nonce,
                    plugin: plugin,
                    toggle_action: action
                }));
            },
            success: function(response) {
                console.log('AJAX response: ' + JSON.stringify(response));
                if (response.success) {
                    console.log('Toggle successful: ' + response.data.status);
                    $link.text(response.data.status === 'enabled' ? 'Disable auto-updates' : 'Enable auto-updates');
                    $link.attr('data-action', response.data.status === 'enabled' ? 'disable' : 'enable');
                    $link.attr('aria-label', response.data.status === 'enabled' ? 'Disable auto-updates' : 'Enable auto-updates');
                } else {
                    console.error('Toggle failed: ' + response.data.message);
                }
                $link.next('.spinner').remove();
                $link.css('pointer-events', 'auto');
            },
            error: function(xhr, status, error) {
                console.error('AJAX error - Status: ' + status + ', Error: ' + error);
                console.error('Response text: ' + xhr.responseText);
                $link.next('.spinner').remove();
                $link.css('pointer-events', 'auto');
            }
        });
    });

    setTimeout(function() {
        var $toggleLinks = $('.teckglobal-bfp-toggle');
        console.log('Fallback check at: ' + new Date().toISOString());
        console.log('Found ' + $toggleLinks.length + ' toggle links');
        if ($toggleLinks.length > 0) {
            console.log('First toggle link in fallback: ' + $toggleLinks[0].outerHTML);
        } else {
            console.warn('No toggle links found. DOM issue or script conflict.');
        }
    }, 2000);

    if ($('#map').length) {
        console.log('Map container found, initializing at: ' + new Date().toISOString());

        // Check if Leaflet is loaded
        if (typeof L === 'undefined') {
            console.error('Leaflet (L) is not defined. Check if leaflet.js is loading correctly.');
            return;
        }

        // Initialize map with a default global view
        var map = L.map('map').setView([0, 0], 1);
        console.log('Map initialized with default view [0, 0] at zoom 1');

        // Add OpenStreetMap tile layer
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
        }).addTo(map);
        console.log('OSM tile layer added');

        // Check for locations data
        var locationsData = typeof locations !== 'undefined' ? locations : [];
        console.log('Locations data received: ' + JSON.stringify(locationsData));

        if (locationsData.length > 0) {
            var markers = L.layerGroup().addTo(map);
            var bounds = [];

            locationsData.forEach(function(location) {
                if (location.lat && location.lng && !isNaN(location.lat) && !isNaN(location.lng)) {
                    var marker = L.marker([location.lat, location.lng]).addTo(markers);
                    marker.bindPopup("<b>IP:</b> " + location.ip + "<br><b>Country:</b> " + location.country);
                    bounds.push([location.lat, location.lng]);
                    console.log('Added marker for IP ' + location.ip + ' at [' + location.lat + ', ' + location.lng + ']');
                } else {
                    console.warn('Invalid coordinates for IP ' + location.ip + ': lat=' + location.lat + ', lng=' + location.lng);
                }
            });

            if (bounds.length > 0) {
                map.fitBounds(bounds, { padding: [50, 50] });
                console.log('Map zoomed to bounds: ' + JSON.stringify(bounds));
            } else {
                console.warn('No valid coordinates found; retaining default view');
            }
        } else {
            console.log('No locations data available to plot');
            var message = L.marker([0, 0], {
                icon: L.divIcon({
                    className: 'map-message',
                    html: 'No banned IPs with location data on this page'
                })
            }).addTo(map);
        }

        // Handle unban button clicks
        $('.teckglobal-unban-ip').on('click', function(e) {
            e.preventDefault();
            var ip = $(this).attr('data-ip');
            if (typeof teckglobal_bfp_ajax === 'undefined') {
                console.error('teckglobal_bfp_ajax not defined');
                return;
            }
            console.log('Unban clicked for IP: ' + ip);

            $.ajax({
                url: teckglobal_bfp_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'teckglobal_bfp_unban_ip',
                    nonce: teckglobal_bfp_ajax.unban_nonce,
                    ip: ip
                },
                success: function(response) {
                    if (response.success) {
                        console.log('IP ' + ip + ' unbanned successfully');
                        var $row = $(this).closest('tr');
                        $row.find('td:nth-child(4)').text('No');
                        $row.find('td:nth-child(5)').text('N/A');
                        $row.find('td:nth-child(10)').html('Ban Expired');
                    } else {
                        console.error('Unban failed: ' + response.data.message);
                    }
                }.bind(this),
                error: function(xhr, status, error) {
                    console.error('AJAX error on unban: ' + error);
                }
            });
        });
    } else {
        console.log('No map container found (expected on plugins.php)');
    }
});
