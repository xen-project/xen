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

function doOp2( op, args )
{
    document.forms[0].op.value = op
    document.forms[0].args.value = args
    document.forms[0].submit()
}
