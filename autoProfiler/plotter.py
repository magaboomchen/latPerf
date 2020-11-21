#!/usr/bin/python
# -*- coding: UTF-8 -*-

import os
import os.path
import csv
import time

import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import drawkit.figure_style as fs


class Plotter(object):
    def __init__(self):
        self.figureSize = fs.LINEof3_FIGURE_SIZE
        self.dataSet = []
        self.dataNum = 0
        self.whis_value = 1.5

    def addLatencyDict(self, latencysDict):
        data = []
        for key,value in sorted(latencysDict.items()):
            latencyList = latencysDict[key]["latencyList"]
            data.append(latencyList)
        self.dataSet.append(data)
        self.dataNum = self.dataNum + 1
        self.xticklabels = range(1,len(latencysDict)+1)

    def drawProfile(self, xlabel_name, ylabel_name, title_name, legendNameSet):
        self.fig, self.ax = plt.subplots(figsize = self.figureSize)
        self.xlabel_name = xlabel_name
        self.ylabel_name = ylabel_name
        self.title_name = title_name
        self.legendNameSet = legendNameSet
        self._drawBoxOnAXES()

    def _drawBoxOnAXES(self):
        self._genPosition()
        self._genBoxWidth()
        self._genBoxStyle()
        self._addBox()
        self._tuneStyle()

    def _genPosition(self):
        if self.dataNum == 1 and len(self.dataSet) != 1:
            # 特殊情况，只有一种box，输入格式可能是一维list，需要改成二维list
            self.dataSet = [self.dataSet]
            print("special case")
        self.pos = np.array( range(len(self.dataSet[0])) ) + 1

    def _genBoxWidth(self):
        self.box_width = 1.0/(self.dataNum + 1)

    def _genBoxStyle(self):
        self.boxprops = []
        self.capprops = []
        self.whiskerprops = []
        self.medianprops = []
        for i in range(self.dataNum):
            self.boxprops.append( dict(linestyle='-',  hatch=fs.patterns[i] ) )
            self.capprops.append( dict(linestyle='-') )
            self.whiskerprops.append( dict(linestyle='-') )
            self.medianprops.append( dict(linestyle='-') )

    def _addBox(self):
        self.boxDictList = []
        for i in range(self.dataNum):
            boxDict = self.ax.boxplot(x = self.dataSet[i],
                positions=self.pos+(i-(self.dataNum-1)*0.5 )*self.box_width,
                widths=self.box_width,
                patch_artist=True,
                whis=self.whis_value,
                showfliers=False,
                boxprops=self.boxprops[i],
                capprops=self.capprops[i],
                whiskerprops=self.whiskerprops[i],
                medianprops=self.medianprops[i]
            )
        self.boxDictList.append(boxDict['boxes'][0])

    def _tuneStyle(self):
        self.ax.legend(self.boxDictList, self.legendNameSet, fontsize=fs.LEGEND_SIZE).get_frame().set_linewidth(fs.LEGEND_EDGE_WIDTH)

        self.ax.grid(linestyle='--', linewidth=fs.GRID_WIDTH)
        
        self.ax.set_axisbelow(True)

        # set xticks
        self.ax.set_xticks(self.pos)
        self.ax.set_xticklabels(self.xticklabels)

        #set x(y) axis (spines)
        self.ax.spines['bottom'].set_linewidth(fs.XY_SPINES_WIDTH)
        self.ax.spines['bottom'].set_color('k')
        self.ax.spines['left'].set_linewidth(fs.XY_SPINES_WIDTH)
        self.ax.spines['left'].set_color('k')
        self.ax.spines['right'].set_linewidth(fs.XY_SPINES_WIDTH)
        self.ax.spines['right'].set_color('k')
        self.ax.spines['top'].set_linewidth(fs.XY_SPINES_WIDTH)
        self.ax.spines['top'].set_color('k')

        #set x(y) label
        plt.xlabel(self.xlabel_name,fontweight='normal',fontsize=fs.XY_LABEL_SIZE,fontname="Times New Roman",color='k',horizontalalignment='center',x=0.5)
        self.ax.xaxis.labelpad = 2.5
        plt.ylabel(self.ylabel_name,fontweight='normal',fontsize=fs.XY_LABEL_SIZE,fontname="Times New Roman",color='k',horizontalalignment='center',y=0.5)
        self.ax.yaxis.labelpad = 2.5
        plt.title(self.title_name,fontweight='normal',fontsize=fs.TITLE_SIZE,fontname="Times New Roman",color='k',horizontalalignment='center',x=0.5,y=1)

        for tick in self.ax.xaxis.get_major_ticks():
            tick.label.set_fontsize(fs.TICK_LABEL_SIZE)
            tick.label.set_fontweight('normal')#tick.label.set_rotation('vertical')
            tick.label.set_color('k')

        for tick in self.ax.yaxis.get_major_ticks():
            tick.label.set_fontsize(fs.TICK_LABEL_SIZE)
            tick.label.set_fontweight('normal')#tick.label.set_rotation('vertical')
            tick.label.set_color('k')

        self.ax.tick_params(direction='in')

        self.fig.tight_layout()

    def saveFig(self, filePath):
        plt.savefig(filePath)
        plt.close('all')

