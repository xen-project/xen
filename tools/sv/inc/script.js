function update( objRef, text )
{
    if ( document.all || document.getElementById )
    {
        obj = ( document.getElementById )? document.getElementById( objRef ) : document.all( objRef );

        obj.innerHTML= text
    }
}

function doOp( op )
{
    document.forms[0].op.value = op
    document.forms[0].submit()
}
