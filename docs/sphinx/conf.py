# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

from importlib import import_module
from pprint import pformat
from docutils.parsers.rst import Directive
from docutils import nodes
from sphinx import addnodes
from sphinx.util import inspect
import sphinx.pycode

# Import from the local working directory
import os
import sys
sys.path.insert(0, os.path.abspath('../..'))
import tinytuya

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = tinytuya.__project__
copyright = tinytuya.__copyright__
author = tinytuya.__author__
release = tinytuya.__version__

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

# Make the default arg values a but neater.
# Based upon https://stackoverflow.com/a/65195854/6740067
original_object_description = inspect.object_description
def object_description(obj, *args, **kwargs):
    odesc = original_object_description(obj, *args, **kwargs)
    if isinstance(obj, dict) and odesc != 'dict(...)':
        odesc = pformat(obj, indent=4, width=68) #.replace("\n", "<br>\n")
        #print( pf )
    return odesc

inspect.object_description = object_description

# Also make it available to be manually called as `.. pprint:: somevar`
# https://stackoverflow.com/a/59883833/6740067
class PrettyPrintDirective(Directive):
    """Render a constant using pprint.pformat and insert into the document"""
    required_arguments = 1

    def run(self):
        module_path, member_name = self.arguments[0].rsplit('.', 1)
        member_data = getattr(import_module(module_path), member_name)
        code = pformat(member_data, 2, width=68)

        literal = nodes.literal_block(code, code)
        literal['language'] = 'python'

        return [
                addnodes.desc_name(text=member_name),
                addnodes.desc_content('', literal)
        ]

extensions = [
   'sphinx.ext.duration',
   'sphinx.ext.doctest',
   'sphinx.ext.autodoc',
   'sphinx.ext.autosummary',
   'sphinx.ext.napoleon',
]

autosummary_generate = True
autosummary_imported_members = True
toc_object_entries = True

napoleon_numpy_docstring = False
#napoleon_use_ivar = True

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

#html_theme = 'alabaster'
html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

autosummary_context = {
    'tinytuya_core_autodocument': tinytuya.document.sphinx_autodocument,
    'tinytuya_core_extradocument': tinytuya.document.sphinx_extradocument,
    'tinytuya_parent_modules': [
        {
            'group': 'Standard Device Modules',
            'template': 'autoclass-fake-module.rst',
            'members': [
                { 'name': 'tinytuya.XenonDevice', 'currentmodule': False },
                { 'name': 'tinytuya.Device', 'currentmodule': False },
                { 'name': 'tinytuya.BulbDevice', 'currentmodule': True },
                { 'name': 'tinytuya.OutletDevice', 'currentmodule': True },
                { 'name': 'tinytuya.CoverDevice', 'currentmodule': True },
            ],
        },
        {
            'group': 'Module Functions',
            'template': 'automodule-tinytuya.rst',
            'members': [
                { 'name': 'tinytuya' },
            ],
        }
    ]
}

saved_junk = { 'objs': {} }

autosummary_skip_modules = ['tinytuya.Cloud']
for grp in autosummary_context['tinytuya_parent_modules']:
    for gmemb in grp['members']:
        autosummary_skip_modules.append( gmemb['name'] )

def autodoc_skip_member_callback( app, what, name, obj, skip, options ):
    if( what == 'module' and getattr(obj, '__module__', '') in autosummary_skip_modules ):
        return True  # Skip it
    if( what == 'attribute' and name in ('API_REGION_HOSTS',) ):
        return True
    doc = getattr(obj, '__doc__', '')
    if doc and ':meta private:\n' in doc:
        return True
    elif doc and ':meta public:\n' in doc:
        return False
    return None  # Use default skipping behavior otherwise

def autodoc_process_docstring_callback( app, obj_type, name, obj, options, lines ):
    if obj_type == 'data' and name.startswith( 'tinytuya.ERR_' ) and isinstance( obj, int ) and obj in tinytuya.error_codes:
        lines[0] = tinytuya.error_codes[obj]

    if obj_type in ('attribute', 'data'):
        if isinstance( obj, dict ) or isinstance( obj, list ) or isinstance( obj, tuple ): # and name.startswith( 'tinytuya.Cloud.' ):
            print('DSTR', obj_type, name, obj)
            if name not in saved_junk['objs']:
                if isinstance( obj, tuple ):
                    saved_junk['objs'][name] = obj
                else:
                    saved_junk['objs'][name] = obj.copy()
            #lines.clear()
            lines.append( '' )
            if not isinstance( obj, tuple ):
                obj.clear()
            lines.append( '' )
            if isinstance( obj, dict ):
                for k in saved_junk['objs'][name]:
                    lines.append( '* **' + str(k) + '** - ' + saved_junk['objs'][name][k] )
            else:
                for k in saved_junk['objs'][name]:
                    lines.append( '* ' + str(k) )
            lines.append('')


def autodoc_process_signature_callback( app, obj_type, name, obj, options, signature, return_annotation ):
    if obj_type == 'attribute' and isinstance( obj, dict ) and name.startswith( 'tinytuya.Cloud.' ):
        return ('{...}', '')
    return None

def setup(app):
    app.connect( 'autodoc-skip-member', autodoc_skip_member_callback )
    app.connect( 'autodoc-process-docstring', autodoc_process_docstring_callback )
    #app.connect( 'autodoc-process-signature', autodoc_process_signature_callback )
    app.add_directive( 'pprint', PrettyPrintDirective )

    # Monkey-patch sphinx.ext.autodoc._dynamic._loader._get_docstring_lines so it actually finds our module
    original_get_docstring_lines = sys.modules['sphinx.ext.autodoc._dynamic._loader']._get_docstring_lines
    def new_get_docstring_lines( props, *args, **kwargs ):
        if props.obj_type == 'module':
            # Save the last-used module
            saved_junk['module'] = props.module_name
        elif props.obj_type == 'data' and props.module_name == 'tinytuya':
            #if 'MAXCOUNT' in props.parts:
            old_module = props.module_name
            # Set module_name to the actual name
            props.module_name = saved_junk['module']
            #print('!!!!', props.obj_type, props.module_name, props.parts )
            ret = original_get_docstring_lines( props, *args, **kwargs )
            # Restore it so it doesn't clobber the text
            props.module_name = old_module
            return ret
        #elif props.module_name == 'tinytuya.Cloud':
        #    props.module_name = 'tinytuya'
        return original_get_docstring_lines( props, *args, **kwargs )
    sys.modules['sphinx.ext.autodoc._dynamic._loader']._get_docstring_lines = new_get_docstring_lines
