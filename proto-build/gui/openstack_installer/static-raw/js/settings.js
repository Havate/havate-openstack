(function($){
    'use strict';
    function getCookie(name) {
        var cookieValue = null;
        if (document.cookie && document.cookie != '') {
            var cookies = document.cookie.split(';');
            for (var i = 0; i < cookies.length; i++) {
                var cookie = jQuery.trim(cookies[i]);
                // Does this cookie string begin with the name we want?
                if (cookie.substring(0, name.length + 1) == (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }
    var csrftoken = getCookie('csrftoken');
    function csrfSafeMethod(method) {
        // these HTTP methods do not require CSRF protection
        return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
    }
    $.ajaxSetup({
        crossDomain: false, // obviates need for sameOrigin test
        beforeSend: function(xhr, settings) {
            if (!csrfSafeMethod(settings.type)) {
                xhr.setRequestHeader("X-CSRFToken", csrftoken);
            }
        }
    });
    $(function(){
        // add functions here
        (function(){
            $('.tab-pane').on("change", 'input', function(e){
                var $tab_pane = $(this).parents('.tab-pane');
                var valid = $tab_pane.find('.form-group.error').length == 0;
                $tab_pane.find('input[type=text]').each(function(e){
                    if(!$(this).val() && !$(this).hasClass('input-not-required')){
                        valid = false;
                    }
                });
                $tab_pane.find('input[type=radio]').each(function(e){
                    if(!$tab_pane.find('input:radio[name="'+ $(this).attr('name')+'"]').is(':checked')){
                        valid = false;
                        console.log('radio-error');
                    }
                });
                if(valid){
                    $('.nav-tabs li a[href="#' + $tab_pane.attr('id') + '"]').removeClass('incomplete-tab');
                }
                else{
                    if($tab_pane.attr('id') != 'settings-scenario'){
                        $('.nav-tabs li a[href="#' + $tab_pane.attr('id') + '"]').addClass('incomplete-tab');
                    }
                }
            });
            $('.tab-pane input').change();
        })();

        (function(){
            $('#id_mac_pool').hide();
            var mac_add = $('#id_mac_pool').val();
            var mac_ar = mac_add.split(':');
            var $control = $('#id_mac_pool').parent();
						$(".fst.short-mac-input").val(mac_ar[3]);
						$(".snd.short-mac-input").val(mac_ar[4]);
						$(".trd.short-mac-input").val(mac_ar[5]);
            /*$control.append('<br>00:25:B5:');
            $control.append('<div class="input-group input-group-sm"> <span class="input-group-addon">00:25:B5:');
            var $temp_input = $('<input></input>').attr('maxlength', 2).addClass('input-block-level short-mac-input');
            if(mac_ar[3]){
                $temp_input.val(mac_ar[3]);
            }
            $control.append($temp_input);
            $control.append(":");
            var $temp_input = $('<input></input>').attr('maxlength', 2).addClass('input-block-level short-mac-input');
            if(mac_ar[4]){
                $temp_input.val(mac_ar[4]);
            }
            $control.append($temp_input);
            $control.append(":");
            var $temp_input = $('<input></input>').attr('maxlength', 2).addClass('input-block-level short-mac-input');
            if(mac_ar[5]){
                $temp_input.val(mac_ar[5]);
            }
            $control.append($temp_input);*/
            $("input.short-mac-input").keypress(function(e){
                var charCode = !e.charCode ? e.which : e.charCode;
                if(!((charCode>=48 && charCode<=57)||(charCode>=65 && charCode<=70)||(charCode>=97 && charCode<=102)))
                    e.preventDefault();
            });
            $("input.short-mac-input").bind("paste",function(e) {
                e.preventDefault();
            });
            $("input.short-mac-input").change(function(e) {
                var $this = $(this);
                var result = "";
                $this.removeClass('error');
                var val = $this.val();
                if(val.length < 2) {
                    $this.addClass('error');
                }
                $("input.short-mac-input").each(function(){
                    result = result + ":" + $(this).val();
                });
                $('#id_mac_pool').val("00:25:B5" + result);
            });
        })();

        (function(){
            $('#id_mac_pool_size').change(function(){
                var $this = $(this);
                var valid = true;
                $this.removeClass('error');
                var val = $this.val();
                if(val.match(/^\d+$/)) {
                    if(val>1000 || val<0){
                        valid = false;
                    }
                }
                else{
                    valid = false;
                }
                if(!valid){
                    $this.addClass('error');
                }
            });
        })();

        (function(){
            $('input.vlan-field').change(function(){
                var $this = $(this);
                var valid = true;
                $this.removeClass('error');
                var val = $this.val();
                if(val.match(/^\d+$/)) {
                    if(val>4096 || val<=0){
                        valid = false;
                    }
                }
                else if(val.match(/^\d+-\d+$/)){
                    var vlan_min = val.split('-')[0];
                    var vlan_max = val.split('-')[1];
                    if((vlan_min>4096 || vlan_min<=0) || (vlan_max>4096 || vlan_max<=0) || (vlan_min>vlan_max)){
                        valid = false;
                    }
                }
                else{
                    valid = false;
                }
                if($this.hasClass('input-not-required') && !$this.val()){
                    valid = true;
                }
                if(!valid){
                    $this.addClass('error');
                }
            });
        })();

        (function(){
            $('input.subnet-field').change(function(){
                var $this = $(this);
                var valid = true;
                $this.removeClass('error');
                var val = $this.val();
                if(val.match(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/\d+$/)) {
                    var subnet = val.split('/')[1];
                    if(subnet<0 || subnet>32){
                        valid=false;
                    }
                }
                else{
                    valid = false;
                }
                if($this.hasClass('input-not-required') && !$this.val()){
                    valid = true;
                }
                if(!valid){
                    $this.addClass('error');
                }
            });
        })();

        (function(){
            $('input.ip-field').change(function(){
                var $this = $(this);
                var valid = true;
                $this.removeClass('error');
                var val = $this.val();
                if(!val.match(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/)){
                    valid = false;
                }
                if($this.hasClass('input-not-required') && !$this.val()){
                    valid = true;
                }
                if(!valid){
                    $this.addClass('error');
                }
            });
        })();

        (function(){

            $('#clear-scenario-radio-button').click(function(e){
                e.preventDefault();
                $('#scenario-list-table').hide();
                $("#scenario-select").val($("#scenario-select option:first").val());
            });
        })();

        (function(){
            $('#scenario-select').change(function(e){
                e.preventDefault();
                var $this = $(this);
                $this.prop('disabled', true);
                $('body').addClass('waiting');
                $('#scenario-list-table').hide();
                //$this.html('Discovering');
                var scenario_name = $(this).val();

                $.ajax({
                    type: 'POST',
                    url: '/scenario_discovery/',
                    dataType: 'json',
                    data: {
                        'hostname': $('#id_ucsm_hostname').val(),
                        'username': $('#id_username').val(),
                        'password': $('#id_password').val(),
                        'scenario_name': scenario_name
                    },
                    error: function(xhr, status, error){
                        $this.prop('disabled', false);
                        $('body').removeClass('waiting');
                        //$this.html('Run Discovery');
                        //alert('no blades discovered - (check ip address/credentials/server discovery is completed on UCSM)');
                    },
                    success: function(data, status, xhr){
                        $('#scenario-list-table').show();
                        $this.prop('disabled', false);
                        $('body').removeClass('waiting');
                        //$this.html('Run Discovery');
                        if(data.length == 0){
                            //alert('no blades discovered - (check ip address/credentials/server discovery is completed on UCSM)');
                            return;
                        }
                        var $tbody = $('#scenario-list-table tbody');
                        $tbody.html('');
                        var $thead = $('#scenario-list-table thead');
                        $thead.html('');
                        var counter = 0;
                        var $temp_thtr = $('<tr></tr>');
                        var $temp_th = $('<th ><input type="hidden" name="scenario_node_number" id="scenario_id_node_number">Node</th>')
                        $temp_thtr.append($temp_th);

                        for (var x in data['roles']){
                            $temp_th = $('<th style="text-align:center;"></th>').html(data['roles'][x]);
                            $temp_thtr.append($temp_th);
                        }
                        $thead.append($temp_thtr);

                        $('#scenario_id_node_number').val(data['nodes'].length);

                        for (var x in data['nodes']){
                            var html_result = data['nodes'][x][2];
                            var text_result = data['nodes'][x][3];
                            var chassis = data['nodes'][x][0];
                            var blade = data['nodes'][x][1];
                            var $temp_row = $('<tr></tr>').addClass('node'+counter);
                            var temp_blade=html_result.split("<br>");
                            var temp_coll_link = 'node-col-'+counter;
                            var $temp_td = $('<td style="width:40%;"></td>').html('<a data-toggle="collapse" style="cursor: pointer;" data-target="#'+temp_coll_link+'" >' +temp_blade[0] +'</a>');
                            if (temp_blade[1].toLowerCase().indexOf("service") >= 0)
                            {
								$temp_row.addClass('spa');
                            }
                            var temp_blade_all=html_result.split(temp_blade[0]+"<br>");
							var $t2_div = $('<div id="'+temp_coll_link+'" class="panel-collapse collapse"></div>');
							var $t3_div = $('<div class="panel-body" style="padding: 0px;"></div>').html(temp_blade_all[1]+'<br>');
                            var $temp_input = $('<input>').attr('type', 'hidden').addClass('node-name-input').attr('name', 'node_name__'+counter).val(text_result);
                            $t3_div.append($temp_input);
                            var $temp_input = $('<input>').attr('type', 'hidden').addClass('chassis-number-input').attr('name', 'chassis_number__'+counter).val(chassis);
                            $temp_td.append($temp_input);
                            var $temp_input = $('<input>').attr('type', 'hidden').addClass('blade-number-input').attr('name', 'blade_number__'+counter).val(blade);
                            $t3_div.append($temp_input);
                            var $temp_div = $("<div></div>").addClass('hidden hostname-ip-container');
                            var $temp_tab = $('<table class="table"></table>');
                            var $temp_tab_tr =$('<tr></tr>');
                            var $temp_tab_td=$('<td></td>');
                            $temp_tab_td.append('<label>Hostname: </label>');
                            $temp_tab_tr.append($temp_tab_td);
                            var $temp_input = $('<input>').attr('type', 'text').addClass('hostname-input').attr('name', 'scenario_hostname__'+counter);
                            var $temp_tab_td=$('<td></td>');
                            $temp_tab_td.append($temp_input);
                            $temp_tab_tr.append($temp_tab_td);
                            $temp_tab.append($temp_tab_tr);
                            var $temp_tab_tr =$('<tr></tr>');
                            var $temp_tab_td=$('<td></td>');
                            $temp_tab_td.append('<label>IP: </label>');
                            $temp_tab_tr.append($temp_tab_td);
                            var $temp_input = $('<input>').attr('type', 'text').addClass('ip-input').attr('name', 'scenario_ip__'+counter);
                            var $temp_tab_td=$('<td></td>');
                            $temp_tab_td.append($temp_input);
                            $temp_tab_tr.append($temp_tab_td);
                            $temp_tab.append($temp_tab_tr);
							$temp_div.append($temp_tab);
                            $t3_div.append($temp_div);
                            $t2_div.append($t3_div);
							$temp_td.append($t2_div);

                            $temp_row.append($temp_td);
                            for (var x in data['roles']){
                                if (temp_blade[1].toLowerCase().indexOf("service") >= 0)
                                {
                                $temp_input = $('<input>').attr('type', 'radio').addClass(data['roles'][x] + '-input').attr('name', 'role-'+counter).data('role', data['roles'][x]).val(data['roles'][x]).attr('disabled');
                                $temp_td = $('<td align="center"></td>').append($temp_input);
                                }
                                else
                                {
                                $temp_input = $('<input>').attr('type', 'radio').addClass(data['roles'][x] + '-input').attr('name', 'role-'+counter).data('role', data['roles'][x]).val(data['roles'][x]);
                                $temp_td = $('<td align="center"></td>').append($temp_input);
                                }

                                $temp_row.append($temp_td);
                            }
                            $tbody.append($temp_row);

                            console.log('input[name=role-'+counter+']');
                            $('input[name=role-'+counter+']').change(function(){
//                            		$('#'+'node-col-'+counter).collapse('show');
 								$(this).parents('tr').find('.collapse').collapse('show');
                                $(this).parents('tr').find('.hostname-ip-container').removeClass('hidden');
                            });
                            counter = counter + 1;
                        }
                        //alert('Discovery Complete');
                        $('.tab-pane').removeClass('active');
                        $('#settings-scenario').addClass('active');
                        $('.nav-tabs > li').removeClass('active');
                        $('#scenario-tab-name').addClass('active');

                        $('.hostname-input, .ip-input').change(function(){
                            var complete = true;
                            $('#scenario-tab-name .incomplete-tab').removeClass('incomplete-tab');
                            $('.hostname-input').each(function(){
                                if(!$(this).val()){
                                    complete = false;
                                }
                            });
                            $('.ip-input').each(function(){
                                if(!$(this).val()){
                                    complete = false;
                                }
                            });

                            if(complete){
                                $('#summary-table-settings').val('scenario');
                                $('#settings-summary-tab').click();
                            }
                        });
                    }
                });
            });
        })();

        (function(){
            $('#run-discovery-button').click(function(e){
                e.preventDefault();
                $('body').addClass('waiting');
                var $this = $(this);
                $this.prop('disabled', true);
                $this.html('Discovering');
                $.ajax({
                    type: 'POST',
                    url: '/node_discovery/',
                    dataType: 'json',
                    data: {
                        'hostname': $('#id_ucsm_hostname').val(),
                        'username': $('#id_username').val(),
                        'password': $('#id_password').val()
                    },
                    error: function(xhr, status, error){
                        $this.prop('disabled', false);
                        $('body').removeClass('waiting');
                        $this.html('Run Discovery');
                        alert('no blades discovered - (check ip address/credentials/server discovery is completed on UCSM)');
                    },
                    success: function(data, status, xhr){
                        $this.prop('disabled', false);
                        $('body').removeClass('waiting');
                        $this.html('Run Discovery');
                        if(data.length == 0){
                            alert('no blades discovered - (check ip address/credentials/server discovery is completed on UCSM)');
                            return;
                        }
                        var $tbody = $('#node-list-table tbody');
                        $tbody.html('');
                        var counter = 0;
                        $('#id_node_number').val(data.length);

                        for (var x in data){
                            var html_result = data[x][0];
                            var text_result = data[x][1];
                            var chassis = data[x][2];
                            var blade = data[x][3];
                            var $temp_row = $('<tr></tr>').addClass('node'+counter);
                            var $temp_td = $('<td></td>').html(html_result);
                            var $temp_input = $('<input>').attr('type', 'hidden').addClass('node-name-input').attr('name', 'node_name__'+counter).val(text_result);
                            $temp_td.append($temp_input);
                            var $temp_input = $('<input>').attr('type', 'hidden').addClass('chassis-number-input').attr('name', 'chassis_number__'+counter).val(chassis);
                            $temp_td.append($temp_input);
                            var $temp_input = $('<input>').attr('type', 'hidden').addClass('blade-number-input').attr('name', 'blade_number__'+counter).val(blade);
                            $temp_td.append($temp_input);
                            $temp_row.append($temp_td);
                            $temp_input = $('<input>').attr('type', 'radio').addClass('aio-input').attr('name', 'aio').val(counter);
                            $temp_td = $('<td></td>').append($temp_input);
                            $temp_row.append($temp_td);
                            $temp_input = $('<input>').attr('type', 'checkbox').addClass('compute-input').attr('name', 'compute__'+counter);
                            $temp_td = $('<td></td>').append($temp_input);
                            $temp_row.append($temp_td);
                            $temp_input = $('<input>').attr('type', 'radio').addClass('network-input').attr('name', 'network').val(counter);
                            $temp_td = $('<td></td>').append($temp_input);
                            $temp_row.append($temp_td);
                            $temp_input = $('<input>').attr('type', 'checkbox').addClass('swift-input').attr('name', 'swift__'+counter);
                            $temp_td = $('<td></td>').append($temp_input);
                            $temp_row.append($temp_td);
                            $temp_input = $('<input>').attr('type', 'checkbox').addClass('cinder-input').attr('name', 'cinder__'+counter);
                            $temp_td = $('<td></td>').append($temp_input);
                            $temp_row.append($temp_td);
                            $tbody.append($temp_row);
                            counter = counter + 1;
                        }
//                         alert('Discovery Complete');
						$this.prop('disabled', true);
                        $this.html('Discovery complete');
                    }
                });
            });
        })();

        (function(){
            $('#deploy-button').click(function(e){
                if($('.incomplete-tab').length>0 && $('#summary-table-settings').val() != 'scenario'){
                    e.preventDefault();
                }
            });
        })();

        (function(){
            $('#settings-summary-tab').click(function(){
                var $this = $(this);
                var $summary = $('#summary-content');
                $summary.html('');
                $summary.append('Cluster Name: ');
                $summary.append($('#id_cluster_name').val());
                $summary.append('<br>');
                $summary.append('Type of Cluster: ');
                $summary.append($('input[name=cluster_type]:checked').data('label'));
                $summary.append('<br>');
                $summary.append('UCSM HostName: ');
                $summary.append($('#id_ucsm_hostname').val());
                $summary.append('<br>');
                $summary.append('Mac Pool: ');
                $summary.append($('#id_mac_pool').val());
                $summary.append('<br>');
                $summary.append('KVM IP Pool: ');
                $summary.append($('#id_kvm_ip_pool').val());
                $summary.append('<br>');
                var $table = $('<table></table>').attr('id', 'summary-node-table');
                var $temp_tr = $('<tr></tr>');
                var $temp_td = $('<th></th>').html('Node');
                $temp_tr.append($temp_td);
                $temp_td = $('<th></th>').html('Role');
                $temp_tr.append($temp_td);
                $table.append($temp_tr);
                console.log($('#summary-table-settings').val());
                if($('#summary-table-settings').val() == 'scenario'){
                    $('#scenario-list-table tbody tr').each(function(i){
                        var $tr = $(this);
                        $temp_tr = $('<tr></tr>');
                        $temp_td = $('<td></td>').html('Chassis ' + $tr.find('.chassis-number-input').val() + '/Blade' + $tr.find('.blade-number-input').val());
                        $temp_tr.append($temp_td);
                        console.log($('input[name=role-'+i+']:selected'));
                        $temp_td = $('<td></td>').html($('input[name=role-'+i+']:checked').data('role'));
                        $temp_tr.append($temp_td);
                        $table.append($temp_tr);
                    });
                }
                else{
                    $('#node-list-table tbody tr').each(function(){
                        var $tr = $(this);
                        $temp_tr = $('<tr></tr>');
                        $temp_td = $('<td></td>').html('Chassis ' + $tr.find('.chassis-number-input').val() + '/Blade' + $tr.find('.blade-number-input').val());
                        $temp_tr.append($temp_td);
                        var role_ar = [];
                        if($tr.find('.aio-input:checked').length){
                            role_ar.push('AIO');
                        }
                        if($tr.find('.compute-input:checked').length){
                            role_ar.push('Compute');
                        }
                        if($tr.find('.network-input:checked').length){
                            role_ar.push('Network');
                        }
                        if($tr.find('.swift-input:checked').length){
                            role_ar.push('Swift');
                        }
                        if($tr.find('.cinder-input:checked').length){
                            role_ar.push('Cinder');
                        }
                        $temp_td = $('<td></td>').html(role_ar.join(', '));
                        $temp_tr.append($temp_td);
                        $table.append($temp_tr);
                    });
                }
                $summary.append($table);
            });
        })();

    });
})(jQuery);
