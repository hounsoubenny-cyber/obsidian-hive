#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Nov 17 08:47:08 2025

@author: hounsousamuel
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import threading
import time, subprocess
import numpy as np
from bokeh.plotting import figure
from bokeh.models import ColumnDataSource, Button, Tabs, Div, Span
from bokeh.layouts import row, column
from bokeh.server.server import Server
from bokeh.application import Application
from bokeh.application.handlers.function import FunctionHandler
from queue import Queue, Empty
from collections import deque
from atexit import register
from ids_ips_ia.ids_ips_utils.logger import get_logger
logger = get_logger()

class RealTimePLot:
    def __init__(self):

        self.queue1 = Queue()
        self.queue2 = Queue()
        self.queue3 = Queue()

        self.event = threading.Event()
        apps = {'/': Application(FunctionHandler(self.make_document))}
        self.server = Server(apps, port=0, allow_websocket_origin=["*"])
        self.end_atexit()
        self.port = self.server.port


    def make_document(self, doc):
        """Crée le document Bokeh - POUR UNE SEULE SESSION"""

        session_data = {
            'source1': ColumnDataSource(data={"x": [], "y": []}),
            'source2': ColumnDataSource(data={"x": [], "y": []}),
            'source3': ColumnDataSource(data={"x": [], "y": []}),
            'deq_x1': deque(maxlen=100),
            'deq_y1': deque(maxlen=100),
            'deq_x2': deque(maxlen=100),
            'deq_y2': deque(maxlen=100),
            'deq_x3': deque(maxlen=100),
            'deq_y3': deque(maxlen=100),
            'start_time1': time.time(),
            'start_time2': time.time(),
            'start_time3': time.time(),
            'running1': True,
            'running2': True,
            'running3': True,
            "recent_scores": deque(maxlen=5),
            "recent_anomalies1": deque(maxlen=5),
            "recent_anomalies2": deque(maxlen=5)
        }

        p1 = figure(title="Anomalies(packets) / sec", width=800, height=800,
                    x_axis_label="secondes(sec)", y_axis_label='Nombre d\'anomalie')
        p1.line(x='x', y='y', line_width=3, color='red', source=session_data['source1'],
                legend_label='Anomalies(packet) par seconde')
        p1.scatter("x","y",source=session_data['source1'],legend_label='points', fill_color='blue', size=3)

        p2 = figure(title="Anomalies(séquence) / sec", width=800, height=800,
                    x_axis_label="secondes(sec)", y_axis_label='Nombre d\'anomalie')
        p2.line(x='x', y='y', line_width=3, color='red', source=session_data['source2'],
                legend_label='Anomalies(packet) par seconde')
        p2.scatter("x","y",source=session_data['source2'],legend_label='points', fill_color='blue', size=3)

        p3 = figure(title="Scores d'anomalies / sec", width=800, height=800,
                    x_axis_label="secondes(sec)", y_axis_label='Scores',y_range=(0, 300))
        p3.line(x='x', y='y', line_width=3, color='red', source=session_data['source3'],
                legend_label='Score en temps réel')
        p3.scatter("x","y",source=session_data['source3'],legend_label='points', fill_color='blue', size=3)

        line_75 = Span(location=75, dimension='width', line_color='green', line_width=1, line_dash='dashed')
        line_125 = Span(location=125, dimension='width', line_color='yellow', line_width=1, line_dash='dashed')
        line_180 = Span(location=180, dimension='width', line_color='orange', line_width=1, line_dash='dashed')
        line_230 = Span(location=230, dimension='width', line_color='red', line_width=1, line_dash='dashed')
        line_280 = Span(location=280, dimension='width', line_color='darkred', line_width=1, line_dash='dashed')

        p3.add_layout(line_75)
        p3.add_layout(line_125)
        p3.add_layout(line_180)
        p3.add_layout(line_230)
        p3.add_layout(line_280)
        p3.legend.location = "top_left"
        p3.legend.click_policy = "hide"

        current_anomalies1_div = Div(
            text="""
            <div style="text-align: center; background: #f8f9fa; padding: 15px; border-radius: 8px; border: 2px solid #dc3545;">
                <h3 style="margin: 0; color: #495057;">🔴 Anomalies Actuelles</h3>
                <p style="font-size: 32px; font-weight: bold; color: #dc3545; margin: 10px 0;">0</p>
            </div>
            """,
            width=200,
            height=120
        )

        recent_anomalies1_div = Div(
            text="""
            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; border: 1px solid #dee2e6;">
                <h4 style="margin: 0 0 10px 0; color: #495057;">📊 5 Dernières Anomalies</h4>
                <p style="margin: 5px 0; font-family: monospace; color: #6c757d;">• Aucune donnée</p>
            </div>
            """,
            width=200,
            height=200
        )

        current_anomalies2_div = Div(
            text="""
            <div style="text-align: center; background: #f8f9fa; padding: 15px; border-radius: 8px; border: 2px solid #fd7e14;">
                <h3 style="margin: 0; color: #495057;">🟠 Anomalies Actuelles</h3>
                <p style="font-size: 32px; font-weight: bold; color: #fd7e14; margin: 10px 0;">0</p>
            </div>
            """,
            width=200,
            height=120
        )

        recent_anomalies2_div = Div(
            text="""
            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; border: 1px solid #dee2e6;">
                <h4 style="margin: 0 0 10px 0; color: #495057;">📊 5 Dernières Anomalies</h4>
                <p style="margin: 5px 0; font-family: monospace; color: #6c757d;">• Aucune donnée</p>
            </div>
            """,
            width=200,
            height=200
        )

        current_score_div = Div(
            text="""
            <div style="text-align: center; background: #f8f9fa; padding: 15px; border-radius: 8px; border: 2px solid #007bff;">
                <h3 style="margin: 0; color: #495057;">🎯 Score Actuel</h3>
                <p style="font-size: 32px; font-weight: bold; color: #007bff; margin: 10px 0;">0.0</p>
            </div>
            """,
            width=200,
            height=120
        )

        recent_scores_div = Div(
            text="""
            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; border: 1px solid #dee2e6;">
                <h4 style="margin: 0 0 10px 0; color: #495057;">📈 5 Derniers Scores</h4>
                <p style="margin: 5px 0; font-family: monospace; color: #6c757d;">• Aucun score</p>
            </div>
            """,
            width=200,
            height=200
        )

        b1_reset = Button(label='Reset', button_type='success')
        b1_pause = Button(label='Pause', button_type='success')
        b2_reset = Button(label='Reset', button_type='success')
        b2_pause = Button(label='Pause', button_type='success')
        b3_reset = Button(label='Reset', button_type='success')
        b3_pause = Button(label='Pause', button_type='success')

        def reset1_local():
            session_data['source1'].data = {"x": [], "y": []}
            session_data['deq_x1'].clear()
            session_data['deq_y1'].clear()
            session_data['recent_anomalies1'].clear()
            session_data['start_time1'] = time.time()
            current_anomalies1_div.text = """
            <div style="text-align: center; background: #f8f9fa; padding: 15px; border-radius: 8px; border: 2px solid #dc3545;">
                <h3 style="margin: 0; color: #495057;">🔴 Anomalies Actuelles</h3>
                <p style="font-size: 32px; font-weight: bold; color: #dc3545; margin: 10px 0;">0</p>
            </div>
            """
            recent_anomalies1_div.text = """
            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; border: 1px solid #dee2e6;">
                <h4 style="margin: 0 0 10px 0; color: #495057;">📊 5 Dernières Anomalies</h4>
                <p style="margin: 5px 0; font-family: monospace; color: #6c757d;">• Aucune donnée</p>
            </div>
            """

        def reset2_local():
            session_data['source2'].data = {"x": [], "y": []}
            session_data['deq_x2'].clear()
            session_data['deq_y2'].clear()
            session_data['recent_anomalies2'].clear()
            session_data['start_time2'] = time.time()
            current_anomalies2_div.text = """
            <div style="text-align: center; background: #f8f9fa; padding: 15px; border-radius: 8px; border: 2px solid #fd7e14;">
                <h3 style="margin: 0; color: #495057;">🟠 Anomalies Actuelles</h3>
                <p style="font-size: 32px; font-weight: bold; color: #fd7e14; margin: 10px 0;">0</p>
            </div>
            """
            recent_anomalies2_div.text = """
            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; border: 1px solid #dee2e6;">
                <h4 style="margin: 0 0 10px 0; color: #495057;">📊 5 Dernières Anomalies</h4>
                <p style="margin: 5px 0; font-family: monospace; color: #6c757d;">• Aucune donnée</p>
            </div>
            """

        def reset3_local():
            session_data['source3'].data = {"x": [], "y": []}
            session_data['deq_x3'].clear()
            session_data['deq_y3'].clear()
            session_data['recent_scores'].clear()
            session_data['start_time3'] = time.time()
            current_score_div.text = """
            <div style="text-align: center; background: #f8f9fa; padding: 15px; border-radius: 8px; border: 2px solid #007bff;">
                <h3 style="margin: 0; color: #495057;">🎯 Score Actuel</h3>
                <p style="font-size: 32px; font-weight: bold; color: #007bff; margin: 10px 0;">0.0</p>
            </div>
            """
            recent_scores_div.text = """
            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; border: 1px solid #dee2e6;">
                <h4 style="margin: 0 0 10px 0; color: #495057;">📈 5 Derniers Scores</h4>
                <p style="margin: 5px 0; font-family: monospace; color: #6c757d;">• Aucun score</p>
            </div>
            """

        def pause1_local():
            session_data['running1'] = not session_data['running1']
            b1_pause.label = 'Pause' if session_data['running1'] else 'Reprendre'

        def pause2_local():
            session_data['running2'] = not session_data['running2']
            b2_pause.label = 'Pause' if session_data['running2'] else 'Reprendre'

        def pause3_local():
            session_data['running3'] = not session_data['running3']
            b3_pause.label = 'Pause' if session_data['running3'] else 'Reprendre'

        b1_reset.on_click(reset1_local)
        b1_pause.on_click(pause1_local)
        b2_reset.on_click(reset2_local)
        b2_pause.on_click(pause2_local)
        b3_reset.on_click(reset3_local)
        b3_pause.on_click(pause3_local)

        anomalies1_layout = row(
            column(current_anomalies1_div, recent_anomalies1_div),
            p1,
            sizing_mode="stretch_width"
        )
        lay1 = column(anomalies1_layout, row(b1_reset, b1_pause))

        anomalies2_layout = row(
            column(current_anomalies2_div, recent_anomalies2_div),
            p2,
            sizing_mode="stretch_width"
        )
        lay2 = column(anomalies2_layout, row(b2_reset, b2_pause))

        scores_layout = row(
            column(current_score_div, recent_scores_div),
            p3,
            sizing_mode="stretch_width"
        )
        lay3 = column(scores_layout, row(b3_reset, b3_pause))

        compare_lay = column(row(lay1, lay2), lay3)

        tabs = Tabs(tabs=[
            ("Anomalies (packets) par seconde", lay1),
            ("Anomalies (séquence) par seconde", lay2),
            ("Scores par seconde", lay3),
            ("Comparaison", compare_lay)
        ])

        doc.add_root(tabs)
        doc.title = 'IDS/IPS'

        def update_local():
            if not self.event.is_set():
                # Mise à jour p1
                try:
                    if session_data['running1']:
                        x, y = self.queue1.get_nowait()
                        session_data['deq_x1'].append(x)
                        session_data['deq_y1'].append(y - session_data['start_time1'])
                        session_data['source1'].data = {
                            "x": list(session_data['deq_y1']),
                            "y": list(session_data['deq_x1'])
                        }
                        session_data['recent_anomalies1'].append(x)

                        current_anomalies1_div.text = f"""
                        <div style="text-align: center; background: #f8f9fa; padding: 15px; border-radius: 8px; border: 2px solid #dc3545;">
                            <h3 style="margin: 0; color: #495057;">🔴 Anomalies Actuelles</h3>
                            <p style="font-size: 32px; font-weight: bold; color: #dc3545; margin: 10px 0;">{x:.0f}</p>
                        </div>
                        """

                        anomalies_html = ""
                        for anomaly in list(session_data['recent_anomalies1']):
                            anomalies_html += f'<p style="margin: 5px 0; font-family: monospace; color: #dc3545;">• {anomaly:.0f}</p>'

                        if not anomalies_html:
                            anomalies_html = '<p style="margin: 5px 0; font-family: monospace; color: #6c757d;">• Aucune donnée</p>'

                        recent_anomalies1_div.text = f"""
                        <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; border: 1px solid #dee2e6;">
                            <h4 style="margin: 0 0 10px 0; color: #495057;">📊 5 Dernières Anomalies</h4>
                            {anomalies_html}
                        </div>
                        """
                except Empty:
                    pass

                # Mise à jour p2
                try:
                    if session_data['running2']:
                        x, y = self.queue2.get_nowait()
                        session_data['deq_x2'].append(x)
                        session_data['deq_y2'].append(y - session_data['start_time2'])
                        session_data['source2'].data = {
                            "x": list(session_data['deq_y2']),
                            "y": list(session_data['deq_x2'])
                        }
                        session_data['recent_anomalies2'].append(x)

                        current_anomalies2_div.text = f"""
                        <div style="text-align: center; background: #f8f9fa; padding: 15px; border-radius: 8px; border: 2px solid #fd7e14;">
                            <h3 style="margin: 0; color: #495057;">🟠 Anomalies Actuelles</h3>
                            <p style="font-size: 32px; font-weight: bold; color: #fd7e14; margin: 10px 0;">{x:.0f}</p>
                        </div>
                        """

                        anomalies_html = ""
                        for anomaly in list(session_data['recent_anomalies2']):
                            anomalies_html += f'<p style="margin: 5px 0; font-family: monospace; color: #fd7e14;">• {anomaly:.0f}</p>'

                        if not anomalies_html:
                            anomalies_html = '<p style="margin: 5px 0; font-family: monospace; color: #6c757d;">• Aucune donnée</p>'

                        recent_anomalies2_div.text = f"""
                        <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; border: 1px solid #dee2e6;">
                            <h4 style="margin: 0 0 10px 0; color: #495057;">📊 5 Dernières Anomalies</h4>
                            {anomalies_html}
                        </div>
                        """
                except Empty:
                    pass

                # Mise à jour p3
                try:
                    if session_data['running3']:
                        x, y = self.queue3.get_nowait()
                        session_data['deq_x3'].append(x)
                        session_data['deq_y3'].append(y - session_data['start_time3'])
                        session_data['source3'].data = {
                            "x": list(session_data['deq_y3']),
                            "y": list(session_data['deq_x3'])
                        }
                        current_score = x
                        session_data['recent_scores'].append(current_score)

                        color = "#28a745"
                        if current_score >= 280:
                            color = "#721c24"
                        elif current_score >= 230:
                            color = "#dc3545"
                        elif current_score >= 180:
                            color = "#fd7e14"
                        elif current_score >= 125:
                            color = "#ffc107"

                        current_score_div.text = f"""
                        <div style="text-align: center; background: #f8f9fa; padding: 15px; border-radius: 8px; border: 2px solid {color};">
                            <h3 style="margin: 0; color: #495057;">🎯 Score Actuel</h3>
                            <p style="font-size: 32px; font-weight: bold; color: {color}; margin: 10px 0;">{current_score:.1f}</p>
                        </div>
                        """

                        scores_html = ""
                        for score in list(session_data['recent_scores']):
                            score_color = "#28a745"
                            if score >= 280:
                                score_color = "#721c24"
                            elif score >= 230:
                                score_color = "#dc3545"
                            elif score >= 180:
                                score_color = "#fd7e14"
                            elif score >= 125:
                                score_color = "#ffc107"

                            scores_html += f'<p style="margin: 5px 0; font-family: monospace; color: {score_color};">• {score:.1f}</p>'

                        if not scores_html:
                            scores_html = '<p style="margin: 5px 0; font-family: monospace; color: #6c757d;">• Aucun score</p>'

                        recent_scores_div.text = f"""
                        <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; border: 1px solid #dee2e6;">
                            <h4 style="margin: 0 0 10px 0; color: #495057;">📈 5 Derniers Scores</h4>
                            {scores_html}
                        </div>
                        """
                except Empty:
                    pass

        doc.add_periodic_callback(update_local, 50)

    def add_data1(self, data):
        self.queue1.put((data, time.time()))

    def add_data2(self, data):
        self.queue2.put((data, time.time()))

    def add_data3(self, data):
        self.queue3.put((data, time.time()))


    def start_server(self):
        apps = {'/': Application(FunctionHandler(self.make_document))}
        self.server = Server(apps, port=0, allow_websocket_origin=["*"])
        self.server.start()
        self.port = self.server.port
        port = self.port
        logger.print(f"🚀 Serveur Bokeh: http://localhost:{port}/")
        # for i in range(0,4):
        #     logger.print(f"Onglet {i} accesible à http://localhost:{port}/?tab={i}")
        self.server.io_loop.start()

    def end(self):
        try:
            self.server.io_loop.stop()
            if not self.server._stopped:
                self.server.stop()
            code = subprocess.run(['fuser','-k',f"{self.server.port}/tcp"], check=False, capture_output=True, )
            # code2 = subprocess.run(['pkill','-f',f":{self.server.port}"], check=False, capture_output=True)
            # logger.print(code.returncode, code2.returncode)
            if code.returncode == 0:
                logger.print(f'Port {self.server.port} fermé avec succès')
            self.event.set()
        except Exception:
            pass

    def end_atexit(self):
        def _end():
            self.end()
            if hasattr(self, 'controle_thread'):
                self.controle_thread.join(2)
        register(_end)

    def control(self):
        self.controle_thread = threading.Thread(target=self.start_server, daemon=True)
        self.controle_thread.start()
        time.sleep(3)  # Atendre le demarrage

if __name__ == '__main__':
    controller = RealTimePLot()
    controller.control()
    logger.print("⏳ Démarrage du serveur...")
    # time.sleep(3)

    logger.print("🎯 JE CONTRÔLE LE GRAPHIQUE MAINTENANT !")
    t = time.time()
    # VOTRE CODE - vous faites ce que vous voulez
    for i in range(2000000):
        try:
            # Générer des données intéressantes
            x = np.random.normal(50, 20)
            x = np.clip(x, 0, 200)

            # Effets visuels sympas

            # VOUS décidez quand mettre à jour
            controller.add_data1(x)

            x = np.random.normal(50, 20)
            x = np.clip(x, 0, 200)

            # Effets visuels sympas

            # VOUS décidez quand mettre à jour
            controller.add_data2(x)

            x = np.random.normal(50, 20)
            x = np.clip(x, 0, 200)

            # Effets visuels sympas

            # VOUS décidez quand mettre à jour
            controller.add_data3(x)

            if i % 20 == 0:
                logger.print(f"📊 Frame {i} envoyée - {x} points")

            time.sleep(0.05)  # 20 FPS
        except KeyboardInterrupt:
            controller.end()
            logger.print("\n👋 Arrêt demandé")
            break

    logger.print("✅ Contrôle terminé - Le serveur continue de tourner")
    logger.print("💡 Arrêtez avec Ctrl+C")
