<?php
/**
 * @package WordPress
 * @subpackage MafiaOffline.ru
 */
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" <?php language_attributes(); ?>>

<head profile="http://gmpg.org/xfn/11">
<meta http-equiv="Content-Type" content="<?php bloginfo('html_type'); ?>; charset=<?php bloginfo('charset'); ?>" />

<title><?php wp_title('&laquo;', true, 'right'); ?> <?php bloginfo('name'); ?></title>

<link rel="stylesheet" href="<?php bloginfo('stylesheet_url'); ?>" type="text/css" media="screen" />
<link rel="alternate" type="application/rss+xml" title="<?php bloginfo('name'); ?> RSS Feed" href="<?php bloginfo('rss2_url'); ?>" />
<link rel="alternate" type="application/atom+xml" title="<?php bloginfo('name'); ?> Atom Feed" href="<?php bloginfo('atom_url'); ?>" />
<link rel="pingback" href="<?php bloginfo('pingback_url'); ?>" />

<script type="text/javascript" src="<?php bloginfo('template_directory'); ?>/javascripts/functions.js" ></script>

<?php if ( is_singular() ) wp_enqueue_script( 'comment-reply' ); ?>

<link rel="shortcut icon" href="<?php echo bloginfo('url'); ?>/favicon.ico" />

<?php wp_head(); ?>

</head>
<body>
<script type='text/javascript'>showFirstTimeScreen(); </script>
<div id="page">


<div id="header">
	<div id="headerimg">
		<a href="<?php echo bloginfo('url'); ?>"><img src="<?php bloginfo('stylesheet_directory'); ?>/images/mafia.gif" alt="<?php echo htmlspecialchars (bloginfo('name'), ENT_QUOTES) ?>" width="400" height="250"/></a>
		<h1><a href="<?php echo bloginfo('url'); ?>/"><?php bloginfo('name'); ?></a></h1>
		<div class="description"><?php bloginfo('description'); ?></div>
	</div>
</div>
<hr />
