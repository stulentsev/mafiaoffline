<?php
/**
 * @package WordPress
 * @subpackage MafiaOffline.ru
 */
?>

<hr />
<div id="footer">
	<div class="layer1">
		<div class="layer2">
			<!-- If you'd like to support WordPress, having the "powered by" link somewhere on your blog is the best way; it's our only promotion or advertising. -->
			<p>
				<?php bloginfo('name'); ?>. Сайт работает на
				<a href="http://wordpress.org/">WordPress</a>. RSS: 
				<a href="<?php bloginfo('rss2_url'); ?>">новые записи</a>,
				<a href="<?php bloginfo('comments_rss2_url'); ?>">комментарии</a>.
				<!-- <?php echo get_num_queries(); ?> queries. <?php timer_stop(1); ?> seconds. -->
				Copyright Добрый фей © <?php echo date ('Y') ?>
			</p>
		</div>
	</div>
</div>

<!-- Gorgeous design by Michael Heilemann - http://binarybonsai.com/kubrick/ -->
<?php /* "Just what do you think you're doing Dave?" */ ?>

		<?php wp_footer(); ?>
</body>
</html>
