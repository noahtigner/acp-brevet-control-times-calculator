<html>
    <head>
        <title>Brevets</title>
    </head>

    <body>

    <h1>List of Brevets</h1>
    <br>

    <form action="" method="post">
        <label for='open_close'>Open or Close</label>
        <select name="open_close">
            <option value="oc">Open/Close</option>
            <option value="o">Open</option>
            <option value="c">Close</option>
        </select>

        <label for='top'>Top</label>
        <select name="top">
            <?php
                for ($i=1; $i<=20; $i++)
                {
                    ?>
                        <option value="<?php echo $i;?>"><?php echo $i;?></option>
                    <?php
                }
            ?>
        </select>

    <input type="submit" name="button" value="Submit"/></form>


        <?php

        $varOpt = $_POST['open_close'];
        $varTop = $_POST['top'];

        if($varOpt=='oc') {
            echo '<h3>listAll</h3>';
            echo "<ul style='padding-left: 5%;'>";
            $varReq = 'http://laptop-service:5000/listAll' . '/json?top=' . $varTop;
            $json = file_get_contents($varReq);
            $obj = json_decode($json);
            $open = $obj->open;
            $close = $obj->close;

            echo "OPEN:\n";
            foreach($open as $l) {
                echo "<li>$l</li>";
            }

            echo "CLOSE:\n";
            foreach($close as $l) {
                echo "<li>$l</li>";
            }
            echo '</ul>';
        }
        if($varOpt=='o') {
            echo '<h3>listOpenOnly</h3>';
            echo "<ul style='padding-left: 5%;'>";
            $varReq = 'http://laptop-service:5000/listOpenOnly' . '/json?top=' . $varTop;
            $json = file_get_contents($varReq);
            $obj = json_decode($json);
            $open = $obj->open;

            echo "OPEN:\n";
            foreach($open as $l) {
                echo "<li>$l</li>";
            }
            echo '</ul>';
        }
        if($varOpt=='c') {
            echo '<h3>listCloseOnly</h3>';
            echo "<ul style='padding-left: 5%;'>";
            $varReq = 'http://laptop-service:5000/listCloseOnly' . '/json?top=' . $varTop;
            $json = file_get_contents($varReq);
            $obj = json_decode($json);
            $close = $obj->close;

            echo "CLOSE:\n";
            foreach($close as $l) {
                echo "<li>$l</li>";
            }
            echo '</ul>';
        }
        ?>

    </body>
</html>
