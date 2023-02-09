package cookietracker;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import java.util.List;
import java.util.ArrayList;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.core.Registration;

import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import javax.swing.border.EmptyBorder;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Arrays;

public class TrackerTab implements BurpExtension, ActionListener
{
    private MontoyaApi api;
    JTextField field;
    JTextField field2;
    DefaultTableModel model;
    private JComboBox<String> colorSelector;
    private JTable table;
    private JPopupMenu popupMenu;
    private JMenuItem menuItemRemove;
    private JMenuItem menuItemRemoveAll;
    private List<Registration> listReg;
    private Logging logging;
    
    private int count=0;
    
    //Color names
    private String[] colorChoices = { "BLUE", "CYAN", "GRAY", "GREEN", "MAGENTA", "ORANGE", "PINK", 
    								  "RED", "YELLOW"};
    //Colors for JTable
    private Color[] bgColors = {Color.BLUE, Color.CYAN, Color.GRAY, Color.GREEN, Color.MAGENTA, 
			   Color.ORANGE, Color.PINK, Color.RED, Color.YELLOW,};

    private Color[] fontColors = {Color.WHITE, Color.BLACK, Color.BLACK, Color.BLACK, Color.BLACK, 
			   Color.BLACK, Color.BLACK, Color.BLACK, Color.BLACK,};

    @Override
    public void initialize(MontoyaApi api)
    {
        this.api = api;
        this.listReg = new ArrayList<Registration>();
        this.logging = api.logging();
        
        //Extender and UI
        api.extension().setName("Cookie/Value tracker");
        api.userInterface().registerSuiteTab("Cookie/Value tracker", constructLoggerTab());
    }

    private Component constructLoggerTab()
    {
    	//Split Pane vertical
    	JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

    	//New JPanel
    	JPanel p = new JPanel();
    	//Field for Cookie/Value to be searched
    	field = new JTextField(40);
    	field.setText("Cookie/Value to be searched");
    	//Field for Comment to be assigned
    	field2 = new JTextField(40);
    	field2.setText("Comment to be assigned");
    	//Color selector
    	colorSelector = new JComboBox<String>(colorChoices);
    	//Button to create a new row with related event
    	JButton b = new JButton("ADD ROW");
    	b.addActionListener(e -> selectionButtonPressed());
    	//Add components to JPanel
    	p.add(field);
    	p.add(field2);
    	p.add(colorSelector);
    	p.add(b);
    	splitPane.setRightComponent(p);

    	//Create table for cookies/values to be tracked
    	this.model = new DefaultTableModel();
    	this.table = new JTable(model) {
		    public Component prepareRenderer(TableCellRenderer renderer, int row, int column)
		    {
		        Component c = super.prepareRenderer(renderer, row, column);

		        // Row Color based on color field
		        if (!isRowSelected(row)) {
		        	String x = (String) super.getModel().getValueAt(row, 3);
	        		
		        	int index = Arrays.binarySearch(colorChoices, x);
		        	c.setBackground(bgColors[index]);
		        	c.setForeground(fontColors[index]);
		        }
		        	
		        return c;
		    }
		    

		    @Override
		    public boolean isCellEditable(int row, int column) {
		       //all cells false
		       return false;
		    }
    	};
    	
    	//Header values of the table
    	model.addColumn("ID");
    	model.addColumn("Cookie/Value");
    	model.addColumn("Name");
    	model.addColumn("Color");

    	//PopupMenu for a row in the table
    	popupMenu = new JPopupMenu();
    	//Menu option for a row
    	menuItemRemove = new JMenuItem("Remove Current Row");
        menuItemRemoveAll = new JMenuItem("Remove All Rows");
        menuItemRemove.addActionListener(this);
        menuItemRemoveAll.addActionListener(this);
        popupMenu.add(menuItemRemove);
        popupMenu.add(menuItemRemoveAll);
        // Set the popup menu for the table
        table.setComponentPopupMenu(popupMenu);
        //Event Listener for the table
        table.addMouseListener(new TableMouseListener(table));
    	
        //Add Scroll pane to table and add it to the pane
        JScrollPane srollPane=new JScrollPane(table);
    	splitPane.setLeftComponent(srollPane);
    	
    	return splitPane;
    }
    
    private void selectionButtonPressed() {
    	//Update counter of rows
    	this.count++;
    	
    	//Retrieve user input
    	String cookie = this.field.getText();
    	String name = this.field2.getText();
    	String stringC = colorSelector.getSelectedItem().toString();
    	this.model.addRow(new Object[]{this.count, cookie, name, stringC});
    	logging.logToOutput("["+name+"]: "+cookie);

    	//Register HTTP handler with Burp.
        Registration r = api.http().registerHttpHandler(new MyHttpHandler(api, cookie, stringC, name));
        this.listReg.add(r);
    }
    
    @Override
    public void actionPerformed(ActionEvent event) {
        //PopupMenu options
    	JMenuItem menu = (JMenuItem) event.getSource();
        if (menu == menuItemRemove) {
            removeCurrentRow();
        } else if (menu == menuItemRemoveAll) {
            removeAllRows();
        }
    }
     
    private void removeCurrentRow() {
        //Remove selected row from the table
    	int selectedRow = table.getSelectedRow();
        model.removeRow(selectedRow);
        listReg.get(selectedRow).deregister();
        listReg.remove(selectedRow);
    }
     
    private void removeAllRows() {
        //Remove all rows from the table
    	int rowCount = table.getRowCount();
        for (int i = 0; i < rowCount; i++) {
            model.removeRow(0);
            listReg.get(0).deregister();
            listReg.remove(0);
        }
    }
}
