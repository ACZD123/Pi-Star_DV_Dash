<?php
/**
 * Dashboard language selector.
 *
 * `$pistarLanguage` names a translation file under /lang/. Each lang file
 * defines a `$lang[]` array keyed by short identifier (e.g. `dashboard`,
 * `admin`). The configure.php editor rewrites the `$pistarLanguage=`
 * assignment below via `sed -i` when the operator picks a different
 * language from the UI.
 */

$pistarLanguage = 'english_uk';
include_once $_SERVER['DOCUMENT_ROOT'] . "/lang/$pistarLanguage.php";
