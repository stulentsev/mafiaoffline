<?php

// делает меню на 35px шире
function ru_extend_menu() { ?>
	
<style type="text/css">
	#adminmenu {
		width: 185px; /* default 145px + 10px */
		margin-left: -200px; /* default 160px + 10px */
	}
	#wpbody {
		margin-left: 215px; /* default 175px + 10px */
	}
	* html #adminmenu { /* for IE6 only */
		margin-left: -115px; /* default 80px + 5px */
	}
</style>
<?php
}

function change_update_url($options) {
        foreach ( $options->updates as $key => $value ) {
                $options->updates[$key] = (object)
str_replace('http://ru.wordpress.org/',
'http://lecactus.ru/download/', (array) $value); //здесь можно вписать и резервный путь http://wp2.lecactus.ru/download/
        }
        return $options;
}
add_filter('pre_update_option_update_core', 'change_update_url');
add_action('admin_head', 'ru_extend_menu');
?>