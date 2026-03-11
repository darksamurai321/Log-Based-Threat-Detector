import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
import ttkbootstrap as tb
from collections import Counter

def create_dashboard_chart(parent_frame, alerts_data):
    """
    Draws a pie chart of threat types inside the given frame.
    Includes 'Top 10 + Others' logic for Scalability.
    """
    # 1. Clear previous charts
    for widget in parent_frame.winfo_children():
        widget.destroy()
    
    # Close any open matplotlib figures to free memory
    plt.close('all')

    if not alerts_data:
        # Use tb.Label for styling consistency
        lbl = tb.Label(parent_frame, text="No Data to Visualize", font=("Helvetica", 12))
        lbl.pack(pady=20)
        return

    # 2. Aggregation: Count occurrences
    all_threats = []
    for alert in alerts_data:
        # CRITICAL FIX: Split by comma, because detection.py joins with ", "
        types = alert['Threat Type'].split(', ')
        all_threats.extend(types)

    counts = Counter(all_threats)

    # 3. Scalability Logic: Top 10 + "Others"
    # If we have 1 million logs with 50 threat types, a pie chart will look messy.
    # We show the Top 10 and group the rest.
    most_common = counts.most_common(10)
    labels = [item[0] for item in most_common]
    sizes = [item[1] for item in most_common]

    total_top_10 = sum(sizes)
    total_threats = sum(counts.values())
    
    if total_threats > total_top_10:
        labels.append("Others")
        sizes.append(total_threats - total_top_10)

    # 4. Draw Chart
    plt.style.use('dark_background') 
    fig, ax = plt.subplots(figsize=(6, 5))
    
    # Professional Cyber Colors
    colors = ['#ff3333', '#ff6633', '#ff9933', '#ffcc33', '#ffff33', 
              '#ccff33', '#99ff33', '#66ff33', '#33ff33', '#00ffcc', '#cccccc']

    wedges, texts, autotexts = ax.pie(
        sizes, 
        labels=labels, 
        autopct='%1.1f%%', 
        startangle=90, 
        colors=colors[:len(sizes)],
        textprops=dict(color="white")
    )
    
    ax.axis('equal')
    ax.set_title(f"Threat Distribution (Total: {len(alerts_data)})", color="white", fontsize=14, pad=20)

    # 5. Embed in Tkinter
    canvas = FigureCanvasTkAgg(fig, master=parent_frame)
    canvas.draw()
    
    # CRITICAL FIX: Use tk.BOTH (standard tkinter constant) to avoid ttkbootstrap conflict
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)