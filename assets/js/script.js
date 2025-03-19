console.log('script.js loaded at: ' + new Date().toISOString());

jQuery(document).ready(function($) {
    console.log('jQuery available: ' + (typeof $ !== 'undefined' ? 'Yes' : 'No'));
    console.log('jQuery document.ready fired at: ' + new Date().toISOString());

    // Auto-update toggle functionality
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

    // Fallback check for toggle links
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

    // Map initialization for IP Logs & Map page
    if ($('#bfp-map').length) { // Adjusted to match functions.php ID
        console.log('Map container found, initializing at: ' + new Date().toISOString());

        if (typeof L === 'undefined') {
            console.error('Leaflet (L) is not defined. Ensure leaflet.js is enqueued.');
            return;
        }

        var map = L.map('bfp-map').setView([0, 0], 2);
        console.log('Map initialized with default view [0, 0] at zoom 2');

        var osmLayer = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
            maxZoom: 18
        }).addTo(map);

        var locationsData = window.teckglobal_bfp_locations || []; // Expecting localized data
        console.log('Locations data received: ' + JSON.stringify(locationsData));

        if (locationsData.length > 0) {
            var markers = L.layerGroup().addTo(map);
            var bounds = [];

            locationsData.forEach(function(location) {
                if (location.lat && location.lng && !isNaN(location.lat) && !isNaN(location.lng)) {
                    var marker = L.marker([location.lat, location.lng]).addTo(markers);
                    marker.bindPopup(
                        '<b>IP:</b> ' + location.ip +
                        '<br><b>Country:</b> ' + location.country +
                        '<br><b>User Agent:</b> ' + location.user_agent
                    );
                    bounds.push([location.lat, location.lng]);
                    console.log('Marker added for IP: ' + location.ip + ' at [' + location.lat + ', ' + location.lng + ']');
                } else {
                    console.warn('Invalid coordinates for IP: ' + location.ip);
                }
            });

            if (bounds.length > 0) {
                map.fitBounds(bounds);
                console.log('Map adjusted to fit bounds: ' + JSON.stringify(bounds));
            }
        } else {
            console.log('No valid locations to display on map.');
        }
    }

    // Unban IP button handler
    $(document).on('click', '.teckglobal-unban-ip', function(e) {
        var $button = $(this);
        if ($button.hasClass('ajax-unban')) {
            e.preventDefault();
            var ip = $button.data('ip');

            if (typeof teckglobal_bfp_ajax === 'undefined') {
                console.error('teckglobal_bfp_ajax not defined for unban action.');
                return;
            }

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
                        $button.replaceWith('<span>Unbanned</span>');
                        console.log('IP ' + ip + ' unbanned successfully via AJAX');
                    } else {
                        console.error('Unban failed: ' + response.data.message);
                    }
                },
                error: function(xhr, status, error) {
                    console.error('Unban AJAX error: ' + error);
                }
            });
        }
    });

    // Visual feedback on login form and CAPTCHA/Attempts notice
    if ($('#loginform').length) {
        console.log('Login form detected, setting up visual feedback at: ' + new Date().toISOString());

        // CAPTCHA integration
        if (teckglobal_bfp_ajax.captcha_enabled) {
            $.getScript('https://www.google.com/recaptcha/api.js', function() {
                $('#loginform p.submit').before(
                    '<div class="g-recaptcha" data-sitekey="' + teckglobal_bfp_ajax.captcha_site_key + '"></div>'
                );
                console.log('reCAPTCHA loaded and added to login form');
            });
        }

        // Attempts left notice
        if (!teckglobal_bfp_ajax.is_banned && teckglobal_bfp_ajax.attempts_left < 5) {
            $('#loginform').prepend(
                '<p class="bfp-attempts-notice">Warning: ' + teckglobal_bfp_ajax.attempts_left +
                ' login attempts remaining before ban.</p>'
            );
            console.log('Added attempts notice: ' + teckglobal_bfp_ajax.attempts_left + ' attempts left');
        }

        $('#loginform').on('submit', function(e) {
            var $form = $(this);
            var isBanned = teckglobal_bfp_ajax.is_banned;

            if (isBanned) {
                e.preventDefault();
                $form.addClass('tgbp-blocked');
                console.log('IP is banned; login form blocked with visual feedback.');
                setTimeout(function() {
                    $form.removeClass('tgbp-blocked');
                }, 1000);
            }
        });
    }

    // Add excluded IP row (for settings page)
    $('#add-excluded-ip').on('click', function() {
        $('#excluded-ips-rows').append(
            '<tr><td><input type="text" name="excluded_ip[]" value="" /></td>' +
            '<td><input type="text" name="excluded_note[]" value="" /></td>' +
            '<td><button type="button" class="button remove-row">Remove</button></td></tr>'
        );
        console.log('Added new excluded IP row');
    });

    // Remove excluded IP row
    $(document).on('click', '.remove-row', function() {
        $(this).closest('tr').remove();
        console.log('Removed excluded IP row');
    });
});
